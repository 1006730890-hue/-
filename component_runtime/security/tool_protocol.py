"""Tool-independent model planning contracts and runtime data references."""
import hashlib
import json
from .drift_runtime import _decode_strict_json


class PlanClarification(ValueError):
    pass


def plan_response_schema(tools):
    tools = list(tools)
    source = {"type":"object","properties":{
        "step_id":{"type":"string"},"path":{"type":"array","items":{"type":["string","integer"]}},
        "mode":{"type":"string","enum":["copy","derive"]}},
        "required":["step_id","path"],"additionalProperties":False}
    step = {"type":"object","properties":{
        "id":{"type":"string"},"tool":{"type":"string","enum":[tool.name for tool in tools]},
        "arguments":{"type":"object"},"depends_on":{"type":"array","items":{"type":"string"}},
        "purpose":{"type":"string","maxLength":240},"argument_sources":{"type":"object","additionalProperties":source}},
        "required":["id","tool","arguments","argument_sources"],"additionalProperties":False}
    return {"type":"object","properties":{"steps":{"type":"array","items":step},
        "clarification_question":{"type":"string"},
        "blocked_requests":{"type":"array","items":{"type":"object","properties":{
            "request":{"type":"string"},"reason":{"type":"string"}},"required":["request","reason"],"additionalProperties":False}}},
        "required":["steps"],"additionalProperties":False}


def call_response_schema(tools, *, allow_clarification=True):
    return {"type":"object","properties":{
        "step_id":{"type":["string","null"]},"tool":{"type":"string","enum":[tool.name for tool in tools]+(["ask_user"] if allow_clarification else [])},
        "args":{"type":"object"}},"required":["step_id","tool","args"],"additionalProperties":False}


def clarification_available(plan, tools, completed, feedback=()):
    """Read known inputs before asking; errors can always be clarified."""
    if feedback:
        return True
    registry={tool.name:tool for tool in tools}
    done=set(completed)
    return not any(step.step_id not in done and set(step.depends_on)<=done
                   and not registry[step.tool_name].high_impact
                   for step in plan.steps)


def plan_review_schema():
    return {"type":"object","properties":{"state":{"type":"string","enum":["ready","repair","needs_input"]},
        "question":{"type":"string"},
        "issues":{"type":"array","items":{"type":"string"}},"reason":{"type":"string"}},
        "required":["state","question","issues","reason"],"additionalProperties":False}


def model_catalog(tools):
    return [{"name":tool.name,"description":tool.description,
             "input_schema":dict(tool.input_schema),"output_schema":dict(tool.output_schema),
             "requires_confirmation":tool.high_impact}
            for tool in tools]


def has_argument_read_dependencies(plan, tools):
    registry={tool.name:tool for tool in tools}
    by_id={step.step_id:step for step in plan.steps}
    return any(source.get("step_id") in by_id
               and not registry[by_id[source["step_id"]].tool_name].high_impact
               for step in plan.steps for source in step.argument_sources.values())


def review_plan(infer, root_instruction, plan, tools, runtime_time):
    registry = {tool.name: tool for tool in tools}
    bindings = []
    for step in plan.steps:
        spec = registry[step.tool_name]
        bindings.append({"step_id":step.step_id,"tool":step.tool_name,
            "required_parameters":list(spec.input_schema.get("required",[])),
            "literal_parameters":dict(step.arguments),
            "parameters_to_resolve_after_reads":dict(step.argument_sources)})
    review = dict(_decode_strict_json(infer("plan_review", {
        "root_instruction":root_instruction,"plan":plan.to_dict(),
        "parameter_bindings":bindings,
        "registered_tools":model_catalog(registry[name] for name in dict.fromkeys(s.tool_name for s in plan.steps)),
        "runtime_time":runtime_time,
        "execution_model": "Plan steps are candidate actions, not a blindly executed script. After each read, the agent proposes the next call from actual observations; every mutation is checked again before execution. A conditional mutation can declare its condition in purpose and its preceding read in depends_on. This plan schema has no separate if/branch field; do not require one or invent a parameter reference to represent a condition.",
        "high_impact_calls":"prepare a request for human confirmation; do not execute yet"})))
    if "state" in review:
        if (set(review) != {"state","question","issues","reason"}
                or review["state"] not in {"ready","repair","needs_input"}):
            raise ValueError("invalid tool plan review state")
        state=review.pop("state")
        review["valid"]=state=="ready"
        review["needs_clarification"]=state=="needs_input"
    if (set(review) != {"valid","needs_clarification","question","issues","reason"}
            or type(review["valid"]) is not bool or type(review["needs_clarification"]) is not bool
            or not isinstance(review["question"], str) or not isinstance(review["issues"], list)
            or any(not isinstance(issue, str) for issue in review["issues"])
            or not isinstance(review["reason"], str) or not review["reason"].strip()
            or review["valid"] and review["needs_clarification"]
            or review["needs_clarification"] and not review["question"].strip()
            or not review["valid"] and not review["needs_clarification"] and not review["issues"]):
        raise ValueError("invalid tool plan review")
    return review


def at_path(value, path):
    for key in path:
        if isinstance(key, str) and isinstance(value, dict):
            value = value[key]
        elif type(key) is int and key >= 0 and isinstance(value, list):
            value = value[key]
        elif isinstance(key, str) and key.isascii() and key.isdigit() and isinstance(value, list):
            value = value[int(key)]
        else:
            raise ValueError("invalid tool result path")
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,
                                     separators=(",", ":"),allow_nan=False).encode()).hexdigest()


def referenced_value(value, path, step_id):
    """Normalize absent transport prefixes; never guess actual data fields."""
    normalized=list(path)
    while True:
        try:
            return at_path(value,normalized), normalized
        except (KeyError,IndexError,ValueError,TypeError):
            if (normalized and normalized[0] in {"output","result","data",step_id}
                    and (not isinstance(value,dict) or normalized[0] not in value)):
                normalized=normalized[1:]
            else:
                raise


def resolve_arguments(plan, step_id, tool_name, arguments, observations, completed):
    """Materialize declared copy references; leave model-derived arguments intact."""
    position = len(completed)
    expected = plan.steps[position] if position < len(plan.steps) else None
    step = expected if expected is not None and expected.tool_name == tool_name else None
    if step_id is not None and step is None:
        raise ValueError("declared tool step is not the next step; dependencies may be incomplete")
    if step is not None and step_id not in {None, step.step_id}:
        raise ValueError("tool proposal step ID does not match the current trajectory position")
    resolved = dict(arguments)
    evidence = {"proposed_arguments":dict(arguments),"constants":{},"sources":{}}
    if step is not None:
        if any(dep not in completed for dep in step.depends_on):
            raise ValueError("tool input dependencies have not completed")
        for name, value in step.arguments.items():
            if name not in step.argument_sources:
                resolved[name] = value
                evidence["constants"][name] = value
        for name, source in step.argument_sources.items():
            observation = next((row for row in observations if row.get("step_id") == source["step_id"]), None)
            if (observation is None or observation.get("quarantined")
                    or source["step_id"] not in completed):
                raise ValueError("argument source is not a completed safe observation")
            data = observation.get("content")
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except ValueError:
                    pass
            value, normalized_path = referenced_value(data, source["path"], source["step_id"])
            mode = source.get("mode", "copy")
            if mode == "copy":
                resolved[name] = value
            elif mode == "derive":
                if name not in resolved:
                    raise ValueError("a derived argument must be generated from the completed observation")
            else:
                raise ValueError("unknown argument source mode")
            evidence["sources"][name] = {
                "step_id":source["step_id"],"path":normalized_path,"declared_path":source["path"],"mode":mode,
                "tool":observation.get("tool"),"tool_arguments":dict(observation.get("arguments") or {}),
                "value_hash":digest(value),
            }
    evidence["resolved_arguments"] = dict(resolved)
    return resolved, evidence


def observation_payload(spec, raw_result):
    if isinstance(raw_result, dict) and (raw_result.get("quarantined") or raw_result.get("isolated")):
        raise ValueError("tool adapter quarantined its result")
    return at_path(raw_result,list(spec.observation_path)) if spec.observation_path else raw_result


def model_observations(observations, budget=6000):
    """Bound model context without truncating stored JSON or copied values."""
    selected=list(observations)[-6:]
    per_item=max(800,budget//max(1,len(selected)))
    result=[]
    def preview(value, string_limit, collection_limit, depth=0):
        if depth>12:return "[预览层级已截断]"
        if isinstance(value,str):return value[:string_limit]
        if isinstance(value,list):return [preview(v,string_limit,collection_limit,depth+1) for v in value[:collection_limit]]
        if isinstance(value,dict):return {k:preview(v,string_limit,collection_limit,depth+1) for k,v in list(value.items())[:collection_limit]}
        return value
    for observation in selected:
        row=dict(observation)
        original=row.get("content", "")
        text=original if isinstance(original,str) else json.dumps(original,ensure_ascii=False)
        if len(text)>per_item:
            try:data=json.loads(text)
            except ValueError:data=text
            string_limit,collection_limit=2000,40
            while True:
                clipped=preview(data,string_limit,collection_limit)
                rendered=json.dumps(clipped,ensure_ascii=False,separators=(",",":"))
                if len(rendered)<=per_item or string_limit<=32:break
                string_limit=max(32,string_limit//2)
                collection_limit=max(1,collection_limit//2)
            row["content"]=rendered
            row["preview_truncated"]=True
            row["full_content_hash"]=hashlib.sha256(text.encode()).hexdigest()
        result.append(row)
    return result


def verify_argument_sources(sources, execute_read):
    """Refuse confirmation when the referenced data has changed since approval."""
    cache = {}
    for source in sources.values():
        tool = source["tool"]
        args = source["tool_arguments"]
        key = json.dumps([tool,args],ensure_ascii=False,sort_keys=True)
        if key not in cache:
            cache[key] = execute_read(tool,args)
        current = at_path(cache[key], source["path"])
        if digest(current) != source["value_hash"]:
            raise ValueError("referenced tool data changed; regenerate the request before confirmation")
