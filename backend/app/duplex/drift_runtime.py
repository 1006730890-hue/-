"""Production-oriented planning, validation, and isolation primitives for DRIFT.

The module deliberately contains no model or web-framework dependency.  A caller
injects a model callback into :class:`SecurePlanner`, then persists the returned
dataclasses. Online calls use ``drift_llm.LLMDynamicValidator``; the deterministic
:class:`DynamicValidator` is retained only for explicit offline fixtures.
Tool output must pass through :class:`InjectionIsolator` before it is returned to
the model.

Properties of these primitives and the deterministic offline validator:

* model output is parsed as strict JSON and can reference registered tools only;
* malformed plans never become executable plans (a trusted explicit fallback is
  the only fallback);
* schema, planned arguments, and dependencies are checked before every call;
* unplanned mutations require authorization visible in the root instruction;
* high-impact calls always require a human confirmation; and
* raw tool output is represented in persisted objects by a digest and a bounded
  preview, never by an unbounded raw payload.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Sequence


ModelCallback = Callable[[str], Any]
AuthorizationChecker = Callable[[str, "ToolSpec", "ProposedCall"], bool]


class ToolEffect(str, Enum):
    """Observable effect of a tool invocation."""

    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"

    @classmethod
    def parse(cls, value: Any) -> "ToolEffect":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().upper())
        except ValueError as exc:
            raise ValueError(f"unknown tool effect: {value!r}") from exc


def _plain_mapping(value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return dict(value)


def _string_tuple(value: Any, *, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{label} must be an array of strings")
    result = tuple(str(item).strip() for item in value)
    if any(not item for item in result):
        raise ValueError(f"{label} cannot contain empty values")
    return result


@dataclass(frozen=True)
class ToolSpec:
    """Trusted registry entry for one tool.

    ``authorization_phrases`` are exact, human-authored phrases used only for an
    *unplanned* WRITE/EXECUTE proposal.  They should contain user-facing verbs
    such as ``("转账", "付款")`` rather than model-generated descriptions.
    """

    name: str
    description: str = ""
    input_schema: Mapping[str, Any] = field(default_factory=dict)
    required_args: tuple[str, ...] = ()
    high_impact: bool = False
    authorization_phrases: tuple[str, ...] = ()
    output_schema: Mapping[str, Any] = field(default_factory=dict)
    observation_path: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        name = str(self.name).strip()
        if not name:
            raise ValueError("tool name cannot be empty")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "input_schema", dict(self.input_schema or {}))
        object.__setattr__(self, "output_schema", dict(self.output_schema or {}))
        object.__setattr__(self, "observation_path", _string_tuple(self.observation_path, label="observation_path"))
        object.__setattr__(self, "required_args", _string_tuple(self.required_args, label="required_args"))
        object.__setattr__(
            self,
            "authorization_phrases",
            _string_tuple(self.authorization_phrases, label="authorization_phrases"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": dict(self.input_schema),
            "required_args": list(self.required_args),
            "high_impact": self.high_impact,
            "authorization_phrases": list(self.authorization_phrases),
            "output_schema":dict(self.output_schema),
            "observation_path":list(self.observation_path),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ToolSpec":
        body = _plain_mapping(payload, label="tool spec")
        return cls(
            name=body.get("name", ""),
            description=str(body.get("description", "")),
            input_schema=_plain_mapping(body.get("input_schema", {}), label="input_schema"),
            required_args=_string_tuple(body.get("required_args", ()), label="required_args"),
            high_impact=bool(body.get("high_impact", False)),
            authorization_phrases=_string_tuple(
                body.get("authorization_phrases", ()), label="authorization_phrases"
            ),
            output_schema=_plain_mapping(body.get("output_schema", {}), label="output_schema"),
            observation_path=_string_tuple(body.get("observation_path", ()), label="observation_path"),
        )


@dataclass(frozen=True)
class PlanStep:
    step_id: str
    tool_name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    depends_on: tuple[str, ...] = ()
    purpose: str = ""
    dynamically_inserted: bool = False
    argument_sources: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        step_id = str(self.step_id).strip()
        tool_name = str(self.tool_name).strip()
        if not step_id or not tool_name:
            raise ValueError("plan step id and tool name cannot be empty")
        object.__setattr__(self, "step_id", step_id)
        object.__setattr__(self, "tool_name", tool_name)
        object.__setattr__(self, "arguments", _plain_mapping(self.arguments, label="step arguments"))
        object.__setattr__(self, "depends_on", _string_tuple(self.depends_on, label="depends_on"))
        object.__setattr__(self, "argument_sources", _plain_mapping(self.argument_sources, label="argument_sources"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "tool_name": self.tool_name,
            "arguments": dict(self.arguments),
            "depends_on": list(self.depends_on),
            "purpose": self.purpose,
            "dynamically_inserted": self.dynamically_inserted,
            "argument_sources": dict(self.argument_sources),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "PlanStep":
        body = _plain_mapping(payload, label="plan step")
        return cls(
            step_id=body.get("step_id", body.get("id", "")),
            tool_name=body.get("tool_name", body.get("tool", "")),
            arguments=_plain_mapping(body.get("arguments", {}), label="step arguments"),
            depends_on=_string_tuple(body.get("depends_on", ()), label="depends_on"),
            purpose=str(body.get("purpose", "")),
            dynamically_inserted=bool(body.get("dynamically_inserted", False)),
            argument_sources=dict(body.get("argument_sources") or {}),
        )


@dataclass(frozen=True)
class SecurePlan:
    plan_id: str
    root_instruction: str
    steps: tuple[PlanStep, ...]
    source: str = "model"
    revision: int = 1
    blocked_requests: tuple[Mapping[str, str], ...] = ()
    clarification_question: str = ""

    def __post_init__(self) -> None:
        plan_id = str(self.plan_id).strip()
        if not plan_id:
            raise ValueError("plan id cannot be empty")
        if self.revision < 1:
            raise ValueError("plan revision must be positive")
        object.__setattr__(self, "plan_id", plan_id)
        object.__setattr__(self, "root_instruction", str(self.root_instruction))
        object.__setattr__(
            self,
            "steps",
            tuple(step if isinstance(step, PlanStep) else PlanStep.from_dict(step) for step in self.steps),
        )
        if isinstance(self.blocked_requests, (str, bytes, Mapping)):
            raise ValueError("blocked_requests must be an array")
        blocked = []
        for item in self.blocked_requests:
            if (not isinstance(item, Mapping) or set(item) != {"request", "reason"}
                    or any(not isinstance(value, str) or not value.strip() for value in item.values())):
                raise ValueError("blocked request requires request and reason strings")
            blocked.append(dict(item))
        object.__setattr__(self, "blocked_requests", tuple(blocked))
        if not isinstance(self.clarification_question,str):
            raise ValueError("clarification_question must be a string")
        if self.clarification_question.strip() and (self.steps or self.blocked_requests):
            raise ValueError("a clarification plan must not contain actions or blocked requests")

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "root_instruction": self.root_instruction,
            "steps": [step.to_dict() for step in self.steps],
            "source": self.source,
            "revision": self.revision,
            "blocked_requests": [dict(item) for item in self.blocked_requests],
            "clarification_question":self.clarification_question,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SecurePlan":
        body = _plain_mapping(payload, label="secure plan")
        raw_steps = body.get("steps", ())
        if isinstance(raw_steps, (str, bytes)) or not isinstance(raw_steps, Sequence):
            raise ValueError("steps must be an array")
        return cls(
            plan_id=body.get("plan_id", ""),
            root_instruction=str(body.get("root_instruction", "")),
            steps=tuple(PlanStep.from_dict(step) for step in raw_steps),
            source=str(body.get("source", "model")),
            revision=int(body.get("revision", 1)),
            blocked_requests=body.get("blocked_requests", ()),
            clarification_question=body.get("clarification_question", ""),
        )


@dataclass(frozen=True)
class ProposedCall:
    tool_name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    step_id: str | None = None
    completed_steps: tuple[str, ...] = ()
    call_id: str = ""

    def __post_init__(self) -> None:
        tool_name = str(self.tool_name).strip()
        if not tool_name:
            raise ValueError("proposed tool name cannot be empty")
        object.__setattr__(self, "tool_name", tool_name)
        object.__setattr__(self, "arguments", _plain_mapping(self.arguments, label="call arguments"))
        object.__setattr__(self, "completed_steps", _string_tuple(self.completed_steps, label="completed_steps"))
        if self.step_id is not None:
            object.__setattr__(self, "step_id", str(self.step_id).strip() or None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "arguments": dict(self.arguments),
            "step_id": self.step_id,
            "completed_steps": list(self.completed_steps),
            "call_id": self.call_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ProposedCall":
        body = _plain_mapping(payload, label="proposed call")
        return cls(
            tool_name=body.get("tool_name", body.get("tool", "")),
            arguments=_plain_mapping(body.get("arguments", {}), label="call arguments"),
            step_id=body.get("step_id"),
            completed_steps=_string_tuple(body.get("completed_steps", ()), label="completed_steps"),
            call_id=str(body.get("call_id", "")),
        )


@dataclass(frozen=True)
class ValidationDecision:
    decision: str
    reason: str
    risk: str = "low"
    matched_step_id: str | None = None
    errors: tuple[str, ...] = ()
    inserted_step: PlanStep | None = None
    effective_plan: SecurePlan | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized = str(self.decision).lower()
        if normalized not in {"allow", "ask", "deny"}:
            raise ValueError(f"invalid validation decision: {self.decision!r}")
        object.__setattr__(self, "decision", normalized)
        object.__setattr__(self, "errors", _string_tuple(self.errors, label="errors"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "risk": self.risk,
            "matched_step_id": self.matched_step_id,
            "errors": list(self.errors),
            "inserted_step": self.inserted_step.to_dict() if self.inserted_step else None,
            "effective_plan": self.effective_plan.to_dict() if self.effective_plan else None,
            "evidence": dict(self.evidence),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ValidationDecision":
        body = _plain_mapping(payload, label="validation decision")
        inserted = body.get("inserted_step")
        effective = body.get("effective_plan")
        return cls(
            decision=str(body.get("decision", "deny")),
            reason=str(body.get("reason", "")),
            risk=str(body.get("risk", "low")),
            matched_step_id=body.get("matched_step_id"),
            errors=_string_tuple(body.get("errors", ()), label="errors"),
            inserted_step=PlanStep.from_dict(inserted) if inserted is not None else None,
            effective_plan=SecurePlan.from_dict(effective) if effective is not None else None,
            evidence=dict(body.get("evidence") or {}),
        )


@dataclass(frozen=True)
class ToolResultEnvelope:
    """Persistable representation of raw tool output.

    The full raw payload is intentionally absent.  ``content_preview`` is
    bounded and intended for human audit views; ``content_hash`` supports
    integrity correlation with an external encrypted/raw evidence store.
    """

    tool_name: str
    content_hash: str
    content_preview: str
    content_length: int
    call_id: str = ""
    content_type: str = "text/plain"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "content_hash": self.content_hash,
            "content_preview": self.content_preview,
            "content_length": self.content_length,
            "call_id": self.call_id,
            "content_type": self.content_type,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ToolResultEnvelope":
        body = _plain_mapping(payload, label="tool result envelope")
        return cls(
            tool_name=str(body.get("tool_name", "")),
            content_hash=str(body.get("content_hash", "")),
            content_preview=str(body.get("content_preview", "")),
            content_length=int(body.get("content_length", 0)),
            call_id=str(body.get("call_id", "")),
            content_type=str(body.get("content_type", "text/plain")),
        )


@dataclass(frozen=True)
class IsolationResult:
    envelope: ToolResultEnvelope
    safe_content: str
    detected: bool
    quarantined: bool
    removed_spans: tuple[tuple[int, int], ...] = ()
    reasons: tuple[str, ...] = ()
    detector_evidence: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        normalized: list[tuple[int, int]] = []
        for span in self.removed_spans:
            if not isinstance(span, Sequence) or len(span) != 2:
                raise ValueError("removed span must be a [start, end] pair")
            normalized.append((int(span[0]), int(span[1])))
        object.__setattr__(self, "removed_spans", tuple(normalized))
        object.__setattr__(self, "reasons", _string_tuple(self.reasons, label="reasons"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "safe_content": self.safe_content,
            "detected": self.detected,
            "quarantined": self.quarantined,
            "removed_spans": [list(span) for span in self.removed_spans],
            "reasons": list(self.reasons),
            "detector_evidence": [dict(item) for item in self.detector_evidence],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "IsolationResult":
        body = _plain_mapping(payload, label="isolation result")
        return cls(
            envelope=ToolResultEnvelope.from_dict(body.get("envelope", {})),
            safe_content=str(body.get("safe_content", "")),
            detected=bool(body.get("detected", False)),
            quarantined=bool(body.get("quarantined", False)),
            removed_spans=tuple(tuple(span) for span in body.get("removed_spans", ())),
            reasons=_string_tuple(body.get("reasons", ()), label="reasons"),
            detector_evidence=tuple(dict(item) for item in body.get("detector_evidence", ())),
        )


class PlanningError(RuntimeError):
    """A candidate plan could not be converted into a safe executable plan."""

    def __init__(self, message: str, *, attempts: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.attempts = attempts


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _stable_plan_id(root_instruction: str, steps: Sequence[PlanStep]) -> str:
    material = _canonical_json(
        {"root_instruction": root_instruction, "steps": [step.to_dict() for step in steps]}
    )
    return "plan-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _extract_callback_payload(value: Any) -> Any:
    """Accept plain callbacks and common chat-client response shapes."""

    if isinstance(value, (str, bytes, Mapping)):
        # Chat adapters commonly attach provider/model/usage/raw metadata next
        # to the assistant content.  Those envelope keys are not planner keys;
        # strict validation applies to the decoded content object itself.
        if isinstance(value, Mapping) and "content" in value:
            return value["content"]
        return value
    content = getattr(value, "content", None)
    if content is not None:
        return content
    return value


def _decode_strict_json(value: Any) -> Mapping[str, Any]:
    value = _extract_callback_payload(value)
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        # json.loads rejects markdown fences, prefixes, and trailing prose.
        def reject_constant(constant: str) -> None:
            raise ValueError(f"non-standard JSON constant: {constant}")

        def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError(f"duplicate JSON key: {key}")
                result[key] = item
            return result

        try:
            value = json.loads(
                value,
                parse_constant=reject_constant,
                object_pairs_hook=reject_duplicate_keys,
            )
        except (json.JSONDecodeError, ValueError) as exc:
            detail = exc.msg if isinstance(exc, json.JSONDecodeError) else str(exc)
            raise ValueError(f"model output is not strict JSON: {detail}") from exc
    if not isinstance(value, Mapping):
        raise ValueError("model plan must be a JSON object")
    return value


class SecurePlanner:
    """Create validated plans from model JSON or a trusted explicit fallback."""

    def __init__(
        self,
        tools: Iterable[ToolSpec],
        model_callback: ModelCallback | None = None,
        repair_callback: ModelCallback | None = None,
    ) -> None:
        registry: dict[str, ToolSpec] = {}
        for spec in tools:
            if spec.name in registry:
                raise ValueError(f"duplicate tool spec: {spec.name}")
            registry[spec.name] = spec
        if not registry:
            raise ValueError("at least one tool spec is required")
        self.tools = registry
        self.model_callback = model_callback
        self.repair_callback = repair_callback

    def create_plan(
        self,
        root_instruction: str,
        *,
        explicit_steps: Sequence[PlanStep | Mapping[str, Any]] | None = None,
    ) -> SecurePlan:
        """Create a plan, failing closed unless a trusted fallback was supplied.

        ``explicit_steps`` belongs to application code (for example a known
        "show balance" workflow), not to model output.  It is validated against
        the same registry and schemas and therefore provides a deterministic
        fallback without trying to infer permissions from user text.
        """

        instruction = str(root_instruction).strip()
        if not instruction:
            raise PlanningError("root instruction cannot be empty")
        errors: list[str] = []
        if self.model_callback is not None:
            prompt = self._planning_prompt(instruction)
            try:
                return self._plan_from_model(self.model_callback(prompt), instruction, source="model")
            except Exception as exc:  # callback and parse failures share fail-closed handling
                errors.append(f"model: {exc}")
                if self.repair_callback is not None:
                    repair_prompt = self._repair_prompt(instruction, errors[-1])
                    try:
                        return self._plan_from_model(
                            self.repair_callback(repair_prompt), instruction, source="model_repair"
                        )
                    except Exception as repair_exc:
                        errors.append(f"repair: {repair_exc}")

        if explicit_steps is not None:
            try:
                steps = tuple(
                    step if isinstance(step, PlanStep) else PlanStep.from_dict(step)
                    for step in explicit_steps
                )
                self._validate_steps(steps)
                return SecurePlan(
                    plan_id=_stable_plan_id(instruction, steps),
                    root_instruction=instruction,
                    steps=steps,
                    source="deterministic_fallback",
                )
            except Exception as exc:
                errors.append(f"fallback: {exc}")

        detail = "; ".join(errors) if errors else "no model callback or explicit fallback"
        raise PlanningError(f"secure plan unavailable: {detail}", attempts=tuple(errors))

    # A short alias reads naturally in orchestrators.
    plan = create_plan

    def _plan_from_model(self, raw: Any, root_instruction: str, *, source: str) -> SecurePlan:
        body = _decode_strict_json(raw)
        if "steps" not in body or set(body) - {"steps", "blocked_requests", "clarification_question"}:
            raise ValueError("plan JSON allows only steps and optional blocked_requests/clarification_question")
        raw_steps = body["steps"]
        if isinstance(raw_steps, (str, bytes)) or not isinstance(raw_steps, Sequence):
            raise ValueError("steps must be a JSON array")
        steps: list[PlanStep] = []
        allowed_keys = {"id", "tool", "arguments", "depends_on", "purpose", "argument_sources"}
        for index, item in enumerate(raw_steps):
            step_body = _plain_mapping(item, label=f"steps[{index}]")
            unknown = set(step_body) - allowed_keys
            if unknown:
                raise ValueError(f"steps[{index}] has unknown keys: {sorted(unknown)}")
            if "id" not in step_body or "tool" not in step_body:
                raise ValueError(f"steps[{index}] requires id and tool")
            if not isinstance(step_body["id"], str) or not isinstance(step_body["tool"], str):
                raise ValueError(f"steps[{index}] id and tool must be strings")
            if "purpose" in step_body and not isinstance(step_body["purpose"], str):
                raise ValueError(f"steps[{index}].purpose must be a string")
            dependencies = step_body.get("depends_on", ())
            if (
                isinstance(dependencies, (str, bytes))
                or not isinstance(dependencies, Sequence)
                or any(not isinstance(item, str) for item in dependencies)
            ):
                raise ValueError(f"steps[{index}].depends_on must contain only strings")
            sources = _plain_mapping(step_body.get("argument_sources", {}), label="argument_sources")
            literal_arguments = _plain_mapping(step_body.get("arguments", {}), label=f"steps[{index}].arguments")
            # Accept an inline reference as the same protocol construct; this
            # is structural normalization, independent of tool or user wording.
            for parameter,value in tuple(literal_arguments.items()):
                if (isinstance(value, Mapping) and {"step_id","path"}.issubset(value)
                        and not set(value) - {"step_id","path","mode"}):
                    sources.setdefault(parameter,dict(value))
                elif isinstance(value,str):
                    match = re.fullmatch(r"\{\{\s*([^\s.{}]+)\.([\w.-]+)\s*\}\}",value)
                    if match and match.group(1) in {step.step_id for step in steps}:
                        # This is a data-only reference to an existing plan
                        # result, not a template interpreter or executable code.
                        sources.setdefault(parameter,{"step_id":match.group(1),
                            "path":match.group(2).split("."),"mode":"copy"})
            # A declared data reference is the value source, never its stale or
            # placeholder literal. Normalize it before validating the template.
            for parameter in sources:
                literal_arguments.pop(parameter, None)
            # Data references imply graph dependencies. The model need not
            # repeat the same edge in two independent places.
            dependencies = list(dependencies)
            for reference in sources.values():
                if isinstance(reference, Mapping) and reference.get("step_id") not in dependencies:
                    dependencies.append(reference.get("step_id"))
            steps.append(
                PlanStep(
                    step_id=step_body["id"],
                    tool_name=step_body["tool"],
                    arguments=literal_arguments,
                    depends_on=tuple(dependencies),
                    purpose=step_body.get("purpose", ""),
                    argument_sources=sources,
                )
            )
        self._validate_steps(tuple(steps))
        return SecurePlan(
            plan_id=_stable_plan_id(root_instruction, steps),
            root_instruction=root_instruction,
            steps=tuple(steps),
            source=source,
            blocked_requests=body.get("blocked_requests", ()),
            clarification_question=body.get("clarification_question", ""),
        )

    def _validate_steps(self, steps: tuple[PlanStep, ...]) -> None:
        seen: set[str] = set()
        for step in steps:
            if step.step_id in seen:
                raise ValueError(f"duplicate step id: {step.step_id}")
            if step.tool_name not in self.tools:
                raise ValueError(f"unknown tool in plan: {step.tool_name}")
            missing_dependencies = set(step.depends_on) - seen
            if missing_dependencies:
                raise ValueError(
                    f"step {step.step_id} has unknown or forward dependencies: "
                    f"{sorted(missing_dependencies)}"
                )
            spec = self.tools[step.tool_name]
            for name, source in step.argument_sources.items():
                if name not in spec.input_schema.get("properties", {}):
                    raise ValueError(f"unknown deferred parameter {name}")
                if (not isinstance(source, Mapping) or not {"step_id", "path"}.issubset(source)
                        or set(source) - {"step_id", "path", "mode"}
                        or source["step_id"] not in step.depends_on
                        or source["step_id"] not in seen
                        or not isinstance(source["path"], list)
                        or source.get("mode", "copy") not in {"copy","derive"}):
                    raise ValueError(f"invalid source dependency for {name}")
            if step.argument_sources:
                # Unknown data-dependent values are bound after the read, rather
                # than invented by the planner to satisfy an interface schema.
                schema = dict(spec.input_schema)
                schema["required"] = [key for key in schema.get("required", ())
                                      if key not in step.argument_sources]
                spec = replace(spec, input_schema=schema,
                               required_args=tuple(key for key in spec.required_args
                                                   if key not in step.argument_sources))
            errors = validate_arguments(spec, step.arguments)
            if errors:
                raise ValueError(f"step {step.step_id} arguments invalid: {'; '.join(errors)}")
            seen.add(step.step_id)

    def _planning_prompt(self, root_instruction: str) -> str:
        catalog = [
            {
                "name": spec.name,
                "description": spec.description,
                "input_schema": dict(spec.input_schema),
                "output_schema":dict(spec.output_schema),
                "required_args": list(spec.required_args),
                "requires_confirmation":spec.high_impact,
            }
            for spec in self.tools.values()
        ]
        return (
            "Create the minimum tool plan for the root instruction. Use no tool calls "
            "(return {\"steps\":[]}) for greetings, conversation, policy/procedure questions, "
            "or questions answerable without tools. Plan "
            "a READ when the task requires actual data from a registered tool, and only plan a mutation "
            "when the current root instruction explicitly requests that mutation. "
            "Choose tools by the documented fact or action, entity ownership, scope "
            "and input/output contracts. Do not substitute a tool returning a different "
            "fact. Interpret identifiers using the registered fields rather than deciding capability from a noun alone. "
            "When a request uses an imprecise name for a supported record, retrieve the matching actual record and explain its real type. "
            "If the requested resource type is genuinely ambiguous, ask a targeted clarification instead of claiming every related query is unavailable. "
            "Do not present supported records as a different unavailable resource type. "
            "Obtain missing data through available tools before asking the user. "
            "Return JSON only, "
            "with exactly this shape: {\"steps\":[{\"id\":\"step-1\",\"tool\":"
            "\"registered_name\",\"arguments\":{},\"argument_sources\":{},\"depends_on\":[],\"purpose\":\"...\"}]}. "
            "Do not add permissions or tools not requested by the root instruction.\n"
            "For a mixed request, plan the independently executable safe queries. "
            "If a necessary entity or parameter cannot be known from user input or registered tools, "
            "return steps:[] and clarification_question with a concise question for that missing information. "
            "This is a normal incomplete task, not a prohibited request. Never guess who or what the user meant. "
            "Only put actions prohibited by policy or outside the registered capabilities in optional blocked_requests, an array "
            "of objects with exactly request and reason string fields. Never invent tools, "
            "agents, destinations or placeholder values to represent an unsupported action. "
            "Requests to extract or export credentials cannot be performed by these tools: "
            "record that part in blocked_requests and still plan the legitimate query. "
            "Do not also add steps that perform the blocked request or extract the credentials. "
            "Return a single JSON object without comments or explanatory text.\n"
            "For a parameter only known after an earlier read, omit its unknown value "
            "from arguments and add optional argument_sources: "
            '{"parameter_name":{"step_id":"earlier-step-id","path":["result_key"],"mode":"copy"}}. '
            "Use mode copy for direct data references and mode derive when the agent must "
            "generate the parameter from the observed data. Never fill unknown parameters "
            "with examples, schema minimums, arbitrary numbers or placeholder text. "
            "The earlier step must appear in depends_on. Do not invent unknown values.\n"
            "Reference syntax example only (these example tool names are not registered): "
            '{"id":"consume","tool":"example_consumer","arguments":{},"depends_on":["read"],'
            '"argument_sources":{"input_field":{"step_id":"read","path":["output_field"],"mode":"copy"}}}. '
            "Do not embed reference objects inside arguments; arguments contains literal values only.\n"
            f"ROOT_INSTRUCTION={json.dumps(root_instruction, ensure_ascii=False)}\n"
            f"REGISTERED_TOOLS={_canonical_json(catalog)}"
        )

    def _repair_prompt(self, root_instruction: str, error: str) -> str:
        return (
            self._planning_prompt(root_instruction)
            + "\nThe previous output was rejected. Produce one corrected JSON object.\n"
            + f"VALIDATION_ERROR={json.dumps(error, ensure_ascii=False)}"
        )


def _json_type_matches(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, Mapping),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def _validate_value(value: Any, schema: Mapping[str, Any], path: str) -> list[str]:
    errors: list[str] = []
    expected = schema.get("type")
    if isinstance(expected, list):
        if not any(_json_type_matches(value, str(item)) for item in expected):
            errors.append(f"{path} has wrong type; expected one of {expected}")
            return errors
    elif expected is not None and not _json_type_matches(value, str(expected)):
        errors.append(f"{path} has wrong type; expected {expected}")
        return errors
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path} is not an allowed value")
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path} does not match the required constant")
    if isinstance(value, Mapping):
        required = schema.get("required", ())
        for name in required:
            if name not in value:
                errors.append(f"{path}.{name} is required")
        properties = schema.get("properties", {})
        if isinstance(properties, Mapping):
            for name, child in value.items():
                if name in properties and isinstance(properties[name], Mapping):
                    errors.extend(_validate_value(child, properties[name], f"{path}.{name}"))
                elif schema.get("additionalProperties") is False:
                    errors.append(f"{path}.{name} is not allowed")
    if isinstance(value, list) and isinstance(schema.get("items"), Mapping):
        for index, child in enumerate(value):
            errors.extend(_validate_value(child, schema["items"], f"{path}[{index}]"))
    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            errors.append(f"{path} is shorter than minLength")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            errors.append(f"{path} is longer than maxLength")
        if "pattern" in schema:
            try:
                if re.search(str(schema["pattern"]), value) is None:
                    errors.append(f"{path} does not match pattern")
            except re.error:
                errors.append(f"{path} uses an invalid registry pattern")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path} is below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path} is above maximum")
    return errors


def validate_arguments(spec: ToolSpec, arguments: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate a tool call against the supported JSON-Schema subset."""

    args = dict(arguments)
    required = set(spec.required_args)
    schema = dict(spec.input_schema)
    schema_required = schema.get("required", ())
    if isinstance(schema_required, Sequence) and not isinstance(schema_required, (str, bytes)):
        required.update(str(name) for name in schema_required)
    errors = [f"$.{name} is required" for name in sorted(required) if name not in args]
    if schema:
        effective = dict(schema)
        effective.setdefault("type", "object")
        errors.extend(_validate_value(args, effective, "$"))
    return tuple(dict.fromkeys(errors))


class DynamicValidator:
    """Validate each proposed call against a secure plan and trusted registry."""

    def __init__(
        self,
        tools: Iterable[ToolSpec],
        authorization_checker: AuthorizationChecker | None = None,
        *,
        tool_permissions: Mapping[str, str | ToolEffect] | None = None,
    ) -> None:
        self.tools = {spec.name: spec for spec in tools}
        if not self.tools:
            raise ValueError("at least one tool spec is required")
        self.authorization_checker = authorization_checker
        # Explicit offline fixtures only; online permissions come from the LLM.
        self.tool_permissions = {name: ToolEffect.parse(value)
                                 for name, value in (tool_permissions or {}).items()}

    def validate(self, plan: SecurePlan, call: ProposedCall) -> ValidationDecision:
        spec = self.tools.get(call.tool_name)
        if spec is None:
            return self._deny("unknown tool", errors=(f"unregistered tool: {call.tool_name}",))
        permission = self.tool_permissions.get(call.tool_name)
        if permission is None:
            return self._deny("offline fixture has no tool permission; use the LLM validator online")
        schema_errors = validate_arguments(spec, call.arguments)
        if schema_errors:
            return self._deny("tool arguments failed schema validation", errors=schema_errors)

        step = self._match_step(plan, call)
        if step is not None:
            missing = tuple(dep for dep in step.depends_on if dep not in call.completed_steps)
            if missing:
                return self._deny(
                    "planned dependencies are incomplete",
                    matched_step_id=step.step_id,
                    errors=tuple(f"dependency not completed: {dep}" for dep in missing),
                )
            mismatches = self._argument_mismatches(step.arguments, call.arguments)
            if mismatches:
                return self._deny(
                    "proposed arguments differ from the approved plan",
                    matched_step_id=step.step_id,
                    errors=mismatches,
                )
            if spec.high_impact:
                return ValidationDecision(
                    decision="ask",
                    reason="high-impact planned action requires human confirmation",
                    risk="high",
                    matched_step_id=step.step_id,
                    effective_plan=plan,
                )
            return ValidationDecision(
                decision="allow",
                reason="call matches the approved plan and completed dependencies",
                risk="low" if permission is ToolEffect.READ else "medium",
                matched_step_id=step.step_id,
                effective_plan=plan,
            )

        if call.step_id:
            # An explicit but non-matching step id is not eligible for dynamic
            # insertion; otherwise a model could evade an argument mismatch.
            return self._deny("proposed step does not match the approved plan")

        if permission is ToolEffect.READ:
            inserted = self._insert_read_step(plan, call)
            effective = replace(plan, steps=plan.steps + (inserted,), revision=plan.revision + 1)
            if spec.high_impact:
                return ValidationDecision(
                    decision="ask",
                    reason="dynamically inserted high-impact read requires human confirmation",
                    risk="high",
                    matched_step_id=inserted.step_id,
                    inserted_step=inserted,
                    effective_plan=effective,
                )
            return ValidationDecision(
                decision="allow",
                reason="safe read was dynamically inserted into the plan",
                risk="low",
                matched_step_id=inserted.step_id,
                inserted_step=inserted,
                effective_plan=effective,
            )

        if not self._root_authorizes(plan.root_instruction, spec, call):
            return self._deny(
                "unplanned mutation is not explicitly authorized by the root instruction"
            )
        return ValidationDecision(
            decision="ask",
            reason="explicitly authorized unplanned mutation requires human confirmation",
            risk="high" if spec.high_impact or permission is ToolEffect.EXECUTE else "medium",
            effective_plan=plan,
        )

    def _match_step(self, plan: SecurePlan, call: ProposedCall) -> PlanStep | None:
        if call.step_id:
            return next(
                (
                    step
                    for step in plan.steps
                    if step.step_id == call.step_id and step.tool_name == call.tool_name
                ),
                None,
            )
        candidates = [step for step in plan.steps if step.tool_name == call.tool_name]
        if len(candidates) == 1:
            return candidates[0]
        exact = [
            step
            for step in candidates
            if not self._argument_mismatches(step.arguments, call.arguments)
        ]
        return exact[0] if len(exact) == 1 else None

    @staticmethod
    def _argument_mismatches(
        planned: Mapping[str, Any], proposed: Mapping[str, Any]
    ) -> tuple[str, ...]:
        errors: list[str] = []
        for key in sorted(set(planned) | set(proposed)):
            if key not in planned:
                errors.append(f"argument {key!r} was not present in the approved plan")
            elif key not in proposed or proposed[key] != planned[key]:
                errors.append(f"argument {key!r} differs from plan")
        return tuple(errors)

    @staticmethod
    def _insert_read_step(plan: SecurePlan, call: ProposedCall) -> PlanStep:
        digest = hashlib.sha256(
            _canonical_json({"tool": call.tool_name, "arguments": dict(call.arguments)}).encode("utf-8")
        ).hexdigest()[:10]
        base = f"dynamic-read-{digest}"
        existing = {step.step_id for step in plan.steps}
        step_id = base
        suffix = 2
        while step_id in existing:
            step_id = f"{base}-{suffix}"
            suffix += 1
        return PlanStep(
            step_id=step_id,
            tool_name=call.tool_name,
            arguments=call.arguments,
            purpose="validator-approved supporting read",
            dynamically_inserted=True,
        )

    def _root_authorizes(self, root: str, spec: ToolSpec, call: ProposedCall) -> bool:
        if self.authorization_checker is not None:
            try:
                return bool(self.authorization_checker(root, spec, call))
            except Exception:
                return False
        normalized_root = " ".join(root.casefold().split())
        for phrase in spec.authorization_phrases:
            needle = " ".join(phrase.casefold().split())
            if not needle:
                continue
            for match in re.finditer(re.escape(needle), normalized_root):
                prefix = normalized_root[max(0, match.start() - 16):match.start()]
                local_clause = re.split(r"[,，。;；!?！？]", prefix)[-1]
                # Phrase matching is deliberately only a conservative fallback.
                # Applications with domain NLP should inject authorization_checker.
                if re.search(
                    r"(?:不要|别|禁止|不得|不可|不能|拒绝|不用|无需|不必)"
                    r"|(?:do\s+not|don't|never|no|without)\b",
                    local_clause,
                ):
                    continue
                return True
        return False

    @staticmethod
    def _deny(
        reason: str,
        *,
        matched_step_id: str | None = None,
        errors: tuple[str, ...] = (),
    ) -> ValidationDecision:
        return ValidationDecision(
            decision="deny",
            reason=reason,
            risk="high",
            matched_step_id=matched_step_id,
            errors=errors,
        )


_DEFAULT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    for pattern in (
        r"^.*\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|system)\s+(?:instructions?|prompts?).*$",
        r"^.*\b(?:system|developer)\s+(?:message|instruction)\s*:.*$",
        r"^.*\byou\s+are\s+now\b.*$",
        r"^.*\b(?:do\s+not|don['’]t)\s+(?:tell|inform)\s+(?:the\s+)?user\b.*$",
        r"^.*(?:忽略|无视)(?:以上|之前|前面|所有|任何)?(?:的)?(?:指令|提示|规则).*$",
        r"^.*(?:系统|开发者)(?:消息|通知|指令)\s*[:：].*$",
        r"^.*你现在是.*$",
        r"^.*(?:不要|禁止)(?:告诉|通知)用户.*$",
        r"^.*(?:无需|不需要|跳过)(?:用户)?(?:再次)?确认.*$",
        # Business-language injection often disguises an imperative as a
        # bill/system/tool workflow instead of saying "ignore previous".
        r"^.*(?:系统|平台|账单|文档|工具|助手|主\s*Agent|子\s*Agent).{0,48}"
        r"(?:要求|需要|指示|请|必须|务必).{0,160}"
        r"(?:转账|转入|转至|支付|汇款|发送|外发|上传|写入|追加|执行|调用).*$",
        r"^.*(?:请|必须|务必|立即).{0,160}"
        r"(?:转账|转入|转至|支付|汇款|发送|外发|上传|写入|追加|执行|调用).*$",
        r"^.*(?:此后|今后|以后).{0,80}(?:请|应|必须).{0,80}"
        r"(?:转账|转入|转至|支付|汇款|发送).*$",
        r"^.*\b(?:please|must|required\s+to).{0,160}\b"
        r"(?:pay|transfer|send|upload|write|execute|call)\b.*$",
    )
)


class InjectionIsolator:
    """Remove detected prompt-injection spans from tool output.

    ``detector`` may return span pairs, dictionaries containing ``start`` and
    ``end``, or an object/dictionary with a ``spans`` collection.  A bare true
    detection without usable spans is quarantined because it cannot be safely
    redacted.  After redaction the content is scanned again; any residual hit or
    detector failure quarantines the whole payload.
    """

    def __init__(self, detector: Callable[[str], Any] | None = None, *, preview_limit: int = 160) -> None:
        if preview_limit < 16:
            raise ValueError("preview_limit must be at least 16")
        self.detector = detector
        self.preview_limit = preview_limit

    def isolate(
        self,
        raw_content: Any,
        *,
        tool_name: str,
        call_id: str = "",
        content_type: str = "text/plain",
    ) -> IsolationResult:
        raw = self._as_text(raw_content)
        envelope = self._envelope(raw, tool_name=tool_name, call_id=call_id, content_type=content_type)
        if isinstance(raw_content, (Mapping, list)):
            return self._isolate_structured(raw_content, envelope)
        try:
            spans, detector_flag = self._detect(raw)
        except Exception as exc:
            return self._quarantine(envelope, f"injection detector failed: {type(exc).__name__}")
        if detector_flag and not spans:
            return self._quarantine(envelope, "detector reported injection without removable spans")
        if not spans:
            return IsolationResult(
                envelope=envelope,
                safe_content=raw,
                detected=False,
                quarantined=False,
            )
        merged = self._merge_and_validate_spans(spans, len(raw))
        if merged is None:
            return self._quarantine(envelope, "detector returned invalid spans")
        safe = self._remove_spans(raw, merged)
        if safe == raw:
            return self._quarantine(envelope, "detected spans could not be removed")
        if raw.strip() and not safe.strip():
            return self._quarantine(envelope, "entire tool result was classified as prompt injection")
        try:
            residual, residual_flag = self._detect(safe)
        except Exception as exc:
            return self._quarantine(envelope, f"post-redaction validation failed: {type(exc).__name__}")
        if residual or residual_flag:
            return self._quarantine(envelope, "prompt injection remained after redaction")
        return IsolationResult(
            envelope=envelope,
            safe_content=safe.strip(),
            detected=True,
            quarantined=False,
            removed_spans=tuple(merged),
            reasons=("prompt-injection spans removed",),
        )

    def _isolate_structured(self, value: Any, envelope: ToolResultEnvelope) -> IsolationResult:
        """Screen string values independently, preserving legitimate fields.

        A transaction memo is an untrusted instruction surface, while the rest
        of that row and the other rows may still answer the user's question.
        Scalar scans use the same detector and fail closed on detector errors.
        The rebuilt result is rescanned before it can enter model context.
        """
        removed: list[tuple[int, int]] = []
        raw = self._as_text(value)
        reasons: list[str] = []
        evidence: list[dict[str, Any]] = []

        def visit(item: Any, path: str) -> Any:
            if isinstance(item, Mapping):
                return {str(key): visit(child, f"{path}.{key}") for key, child in item.items()}
            if isinstance(item, list):
                return [visit(child, f"{path}[{index}]") for index, child in enumerate(item)]
            if not isinstance(item, str) or not item.strip():
                return item
            spans, flagged, detector = self._scan(item)
            if not spans and not flagged:
                return item
            # Remove the complete contaminated field, including authority
            # impersonation surrounding the actual imperative. Never invent
            # a substitute transaction amount or recipient.
            encoded = _canonical_json(item)
            start = raw.find(encoded)
            if start >= 0:
                removed.append((start, start + len(encoded)))
            reasons.append(f"untrusted instruction field isolated: {path}")
            evidence.append({"path": path, "raw_text": item, "detector": detector,
                             "matched_spans": [list(span) for span in spans]})
            return "[已隔离可疑文本]"

        try:
            cleaned = visit(value, "result")
            safe = _canonical_json(cleaned)
            residual, flagged = self._detect(safe)
        except Exception as exc:
            return self._quarantine(envelope, f"structured injection detector failed: {type(exc).__name__}")
        if residual or flagged:
            return self._quarantine(envelope, "prompt injection remained after structured isolation")
        return IsolationResult(envelope=envelope, safe_content=safe,
                               detected=bool(reasons), quarantined=False,
                               removed_spans=tuple(removed), reasons=tuple(reasons),
                               detector_evidence=tuple(evidence))

    @staticmethod
    def _as_text(value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        try:
            return _canonical_json(value)
        except (TypeError, ValueError):
            return str(value)

    def _envelope(
        self, raw: str, *, tool_name: str, call_id: str, content_type: str
    ) -> ToolResultEnvelope:
        normalized_preview = re.sub(r"\s+", " ", raw).strip()
        if len(normalized_preview) > self.preview_limit:
            normalized_preview = normalized_preview[: self.preview_limit - 1] + "…"
        return ToolResultEnvelope(
            tool_name=tool_name,
            content_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            content_preview=normalized_preview,
            content_length=len(raw),
            call_id=call_id,
            content_type=content_type,
        )

    def _detect(self, text: str) -> tuple[list[tuple[int, int]], bool]:
        spans, flagged, _evidence = self._scan(text)
        return spans, flagged

    def _scan(self, text: str) -> tuple[list[tuple[int, int]], bool, Mapping[str, Any]]:
        spans = [(match.start(), match.end()) for pattern in _DEFAULT_INJECTION_PATTERNS for match in pattern.finditer(text)]
        flagged = bool(spans)
        if self.detector is None:
            return spans, flagged, {"source": "built_in_patterns", "detected": flagged}
        result = self.detector(text)
        external_spans, external_flag = self._normalise_detector_result(result)
        spans.extend(external_spans)
        evidence = result.get("detector", {}) if isinstance(result, Mapping) else {}
        return spans, flagged or external_flag, evidence

    @classmethod
    def _normalise_detector_result(cls, result: Any) -> tuple[list[tuple[int, int]], bool]:
        if result is None or result is False:
            return [], False
        if result is True:
            return [], True
        if isinstance(result, Mapping):
            if "spans" in result:
                spans = cls._normalise_spans(result.get("spans"))
                return spans, bool(result.get("detected", result.get("is_injection", bool(spans))))
            if "start" in result and "end" in result:
                return [(int(result["start"]), int(result["end"]))], True
            return [], bool(result.get("detected", result.get("is_injection", False)))
        spans_attr = getattr(result, "spans", None)
        if spans_attr is not None:
            spans = cls._normalise_spans(spans_attr)
            flag = getattr(result, "detected", getattr(result, "is_injection", bool(spans)))
            return spans, bool(flag)
        spans = cls._normalise_spans(result)
        return spans, bool(spans)

    @staticmethod
    def _normalise_spans(value: Any) -> list[tuple[int, int]]:
        if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
            raise ValueError("detector spans must be iterable")
        spans: list[tuple[int, int]] = []
        for item in value:
            if isinstance(item, Mapping):
                spans.append((int(item["start"]), int(item["end"])))
            elif hasattr(item, "start") and hasattr(item, "end"):
                start_attr = item.start
                end_attr = item.end
                start = start_attr() if callable(start_attr) else start_attr
                end = end_attr() if callable(end_attr) else end_attr
                spans.append((int(start), int(end)))
            elif isinstance(item, Sequence) and len(item) == 2:
                spans.append((int(item[0]), int(item[1])))
            else:
                raise ValueError("invalid detector span")
        return spans

    @staticmethod
    def _merge_and_validate_spans(
        spans: Sequence[tuple[int, int]], content_length: int
    ) -> list[tuple[int, int]] | None:
        ordered = sorted(spans)
        if any(start < 0 or end <= start or end > content_length for start, end in ordered):
            return None
        merged: list[tuple[int, int]] = []
        for start, end in ordered:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged

    @staticmethod
    def _remove_spans(text: str, spans: Sequence[tuple[int, int]]) -> str:
        chunks: list[str] = []
        cursor = 0
        for start, end in spans:
            chunks.append(text[cursor:start])
            cursor = end
        chunks.append(text[cursor:])
        return "".join(chunks)

    @staticmethod
    def _quarantine(envelope: ToolResultEnvelope, reason: str) -> IsolationResult:
        return IsolationResult(
            envelope=envelope,
            safe_content="",
            detected=True,
            quarantined=True,
            reasons=(reason,),
        )


__all__ = [
    "DynamicValidator",
    "InjectionIsolator",
    "IsolationResult",
    "PlanStep",
    "PlanningError",
    "ProposedCall",
    "SecurePlan",
    "SecurePlanner",
    "ToolEffect",
    "ToolResultEnvelope",
    "ToolSpec",
    "ValidationDecision",
    "validate_arguments",
]
