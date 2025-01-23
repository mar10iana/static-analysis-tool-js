import copy
import esprima
import json
import os
import sys

INDENT = 4

### global variables to avoid passing them as argument
# pattern variables
vulnerability = ""
sources = []
sanitizers = []
sinks = []
implicit = False
flows = []

# path variables
variables = []  # list of declared variables
taint_map = {}  # maps variable name to [src, line, is_implicit, [sanitizers]]

# keep track of variables for each path
curr_contexts = []  # list of [variables, taint_map] for each path
curr_context_index = 0

# to detect implicit flows
implicit_sources = []


class Flow:
    def __init__(self, vulnerability, source, sink, unsanitized_flows, sanitized_flows, implicit):
        self.vulnerability = vulnerability
        self.source = source
        self.sink = sink
        self.unsanitized_flows = unsanitized_flows
        self.sanitized_flows = sanitized_flows
        self.implicit = implicit
        self.index = 0

    def __eq__(self, other):
        if isinstance(other, Flow):
            return (self.vulnerability == other.vulnerability and
                    self.source == other.source and
                    self.sink == other.sink)
        return False

    def __hash__(self):
        return hash((self.vulnerability, self.source, self.sink))

    def set_index(self, index):
        self.index = index
        return self

    def merge_sanitized_flows(self, other):
        """ merge the same source -> sink flows with its different sanitized flows
            and set the unsanitized_flows to True if there is an unsanitized flow i.e. empty list """
        #print(f"merging {self.sanitized_flows} with {other.sanitized_flows} for {self.vulnerability}{self.source}") # DEBUG

        # if any of the flows is unsanitized i.e. empty list
        if self.sanitized_flows == [] or other.sanitized_flows == []:
            self.unsanitized_flows = True

        if self.implicit or other.implicit:
            self.implicit = True

        # other will always have at most one sanitized flow
        if other.sanitized_flows != [] and other.sanitized_flows[0] not in self.sanitized_flows:
            # accumulate sanitized flows to self i.e. merge other into self
            self.sanitized_flows.extend(other.sanitized_flows)
            #print(f"\t\t merged {self.sanitized_flows}") # DEBUG
        #else:
            #print(f"no merge, since it is already in the list") #DEBUG

    def to_dict(self):
        return {
            "vulnerability": f"{self.vulnerability}_{self.index}",
            "source": self.source,
            "sink": self.sink,
            "unsanitized_flows": "yes" if self.unsanitized_flows else "no",
            "sanitized_flows": self.sanitized_flows,
            "implicit": "yes" if self.implicit else "no"
        }


def report_flows(source, sink):
    if sink is not None:
        for src, line, is_implicit, sanitized_flow in source:
            new_flow = Flow(
                vulnerability=vulnerability,
                source=[src, line],
                sink=sink,
                unsanitized_flows=False, # by default and if it finds empty list turn to True (see handle_repeated_flows)
                sanitized_flows=[sanitized_flow] if sanitized_flow != [] else [],
                implicit=is_implicit
            )
            #print(f"\n reporting flow -> {new_flow.to_dict()}\n") # DEBUG
            # add every flow even if it is repeated to track sanitized flows
            flows.append(new_flow)


def efficient_append(l1, item):
    if item not in l1:
        l1.append(item)


def efficient_extend(l1, l2):
    for item in l2:
        efficient_append(l1, item)


def traverse_cond_and_append_implicit(node):
    expression_sources = traverse_ast(node)
    if implicit: # pattern requires to track implicit flows
        for src in expression_sources:
            src[2] = True
            efficient_append(implicit_sources, src)


def process_identifier(node):
    """ returns a non-empty list if the identifier is a source or propagated from a source """
    taint_sources = []

    if node['name'] in taint_map:
        efficient_extend(taint_sources, taint_map[node['name']])

    if node['name'] in sources or node['name'] not in variables:
        efficient_append(taint_sources, [node['name'], node['loc']['start']['line'], False, []])

    return taint_sources


def process_assignment(node):
    left = node['left']
    right = node['right']

    taint_sources = traverse_ast(right)
    efficient_extend(taint_sources, implicit_sources) # implicit is tracked for potential sinks

    if left['type'] == 'MemberExpression':

        object_name = left['object']['name'] if 'name' in left['object'] else None
        property_name = left['property']['name'] if 'name' in left['property'] else None

        if object_name in sinks:
            sink = [object_name, left['loc']['start']['line']]
            report_flows(taint_sources, sink)

        if property_name in sinks:
            sink = [property_name, left['loc']['start']['line']]
            report_flows(taint_sources, sink)

        # propagate taint to object
        if object_name in taint_map:
            # since it can be tainted by other of its properties
            efficient_extend(taint_map[object_name], taint_sources)
        taint_map[object_name] = taint_sources

    else:
        sink = [left['name'], left['loc']['start']['line']] if left['name'] in sinks else None
        if taint_sources:
            report_flows(taint_sources, sink)
            taint_map[left['name']] = taint_sources

    if not taint_sources:
        if left['type'] == 'Identifier' and left['name'] in taint_map:
            del taint_map[left['name']]
        elif left['type'] == 'MemberExpression':
            if object_name and object_name in taint_map:
                del taint_map[object_name]

    if right['type'] == 'CallExpression' and right['callee']['name'] in sanitizers:
        sanitizer = [right['callee']['name'], right['callee']['loc']['start']['line']]
        for src in taint_sources:
            if sanitizer not in src[3]: # only append different sanitizers
                src[3].append(sanitizer)

    if left['type'] == 'Identifier':
        efficient_append(variables, left['name'])

    return taint_sources


def process_function_call(node):
    callee = node['callee']

    taint_sources = []

    for arg in node['arguments']:
        efficient_extend(taint_sources, traverse_ast(arg))
    #efficient_extend(taint_sources, implicit_sources) # implicit is tracked for potential sinks and sanitizers

    if callee['type'] == 'MemberExpression':

        object_name = callee['object']['name'] if 'name' in callee['object'] else None
        property_name = callee['property']['name'] if 'name' in callee['property'] else None

        if object_name in sanitizers:
            sanitizer = [object_name, callee['loc']['start']['line']]
            for src in taint_sources:
                if sanitizer not in src[3]: # only append different sanitizers
                    src[3].append(sanitizer)

        if property_name in sanitizers:
            sanitizer = [property_name, callee['loc']['start']['line']]
            for src in taint_sources:
                if sanitizer not in src[3]: # only append different sanitizers
                    src[3].append(sanitizer)


        efficient_extend(taint_sources, implicit_sources) # implicit is tracked for potential sinks after sanitization process

        if property_name in sinks:
            report_flows(taint_sources, [object_name, callee['loc']['start']['line']])        
        if object_name in sinks:
            report_flows(taint_sources, [object_name, callee['loc']['start']['line']])

        if object_name in sources or object_name not in variables:
            efficient_append(taint_sources, [object_name, callee['loc']['start']['line'], False, []])
        if property_name in sources:
            efficient_append(taint_sources, [property_name, callee['loc']['start']['line'], False, []])

    else:
        sink = [callee['name'], callee['loc']['start']['line']] if callee['name'] in sinks else None
        if callee['name'] in sanitizers:
            sanitizer = [callee['name'], callee['loc']['start']['line']]
            #print(f"sanitizer {sanitizer}") # DEBUG
            for src in taint_sources:
                if sanitizer not in src[3]: # only append different sanitizers
                    src[3].append(sanitizer)

        efficient_extend(taint_sources, implicit_sources) # implicit is tracked for potential sinks after sanitization process

        report_flows(taint_sources, sink)

        if callee['name'] in sources:
            efficient_append(taint_sources, [callee['name'], callee['loc']['start']['line'], False, []])

    return taint_sources


def process_binary_expression(node):

    left_sources = traverse_ast(node['left'])
    right_sources = traverse_ast(node['right'])

    return left_sources + right_sources


def process_if_statement(node, context_index):
    global curr_contexts, implicit_sources

    # keep reference to previous contexts
    previous_contexts = curr_contexts.copy()

    # evaluate the condition
    previous_implicit = copy.deepcopy(implicit_sources)
    traverse_cond_and_append_implicit(node['test'])

    # split in branches creating a deepcopy of just the current context
    consequent_contexts = [copy.deepcopy(previous_contexts[context_index])]
    alternate_contexts = [copy.deepcopy(previous_contexts[context_index])]

    curr_contexts = consequent_contexts
    traverse_ast(node['consequent'])
    consequent_contexts = curr_contexts.copy()

    curr_contexts = alternate_contexts
    if 'alternate' in node:
        traverse_ast(node['alternate'])
    alternate_contexts = curr_contexts.copy()

    # restore previous context appending both paths and subpaths
    curr_contexts = previous_contexts
    curr_contexts[context_index] = consequent_contexts[0]
    curr_contexts.extend(consequent_contexts[1:])
    curr_contexts.extend(alternate_contexts)
    implicit_sources = previous_implicit


def process_while_statement(node, context_index):
    global curr_contexts, implicit_sources
    n = len(node['body'])

    # Keep reference to previous contexts
    previous_contexts = curr_contexts.copy()
    previous_implicit = copy.deepcopy(implicit_sources)

    # List to hold the contexts for all iterations
    all_contexts = []

    for i in range(n + 1): # runs <number of nodes in body> + 1 contexts
        current_iteration_contexts = [copy.deepcopy(previous_contexts[context_index])]

        curr_contexts = current_iteration_contexts

        if node['type'] == 'WhileStatement':
            # Traverse the AST the specified number of times
            traverse_cond_and_append_implicit(node['test']) # first test
            for _ in range(i):
                traverse_ast(node['body'])
                traverse_cond_and_append_implicit(node['test']) # test before leaving while

        else: # DoWhileStatement
            for _ in range(i):
                traverse_ast(node['body'])
                traverse_cond_and_append_implicit(node['test']) # test before leaving while

        # Save the updated contexts after this iteration
        all_contexts.extend(curr_contexts.copy())

    # Restore previous context appending all paths and subpaths
    curr_contexts = previous_contexts
    curr_contexts[context_index] = all_contexts[0]
    curr_contexts.extend(all_contexts[1:])
    implicit_sources = previous_implicit


def process_member_expression(node):
    taint_sources = []

    object_name = node['object']['name']
    property_name = node['property']['name']

    if object_name in sources or object_name not in variables:
        efficient_append(taint_sources, [object_name, node['loc']['start']['line'], False, []])

    if property_name in sources:
        efficient_append(taint_sources, [property_name, node['loc']['start']['line'], False, []])

    efficient_extend(taint_sources, implicit_sources) # implicit is tracked for potential sinks

    if property_name in sinks:
        report_flows(taint_sources, [property_name, node['loc']['start']['line']])        
    if object_name in sinks:
        report_flows(taint_sources, [object_name, node['loc']['start']['line']])

    return taint_sources


def process_sequence_expression(node):
    taint_sources = []
    for expression in node['expressions']:
        curr_exp_srcs = traverse_ast(expression)
    efficient_extend(taint_sources, curr_exp_srcs)
    return taint_sources


def process_node(node):
    if node['type'] == 'ExpressionStatement':
        return traverse_ast(node['expression'])

    if node['type'] == 'Identifier':
        return process_identifier(node)

    if node['type'] == 'Literal':
        return []

    if node['type'] == 'AssignmentExpression':
        return process_assignment(node)

    if node['type'] == 'CallExpression':
        return process_function_call(node)

    if node['type'] == 'BinaryExpression' or node['type'] == 'LogicalExpression':
        return process_binary_expression(node)

    if node['type'] == 'UnaryExpression':
        return traverse_ast(node['argument'])
    
    if node['type'] == 'IfStatement':
        process_if_statement(node, curr_context_index)
        return []

    if node['type'] == 'WhileStatement' or node['type'] == 'DoWhileStatement':
        process_while_statement(node, curr_context_index)
        return []
    
    if node['type'] == 'MemberExpression':
        return process_member_expression(node)
    
    if node['type'] == 'SequenceExpression':
        return process_sequence_expression(node)

    if node['type'] == 'Program' or node['type'] == 'BlockStatement':
        traverse_ast(node['body'])
        return []

    #print(f">\t>\t>\t>\t>\tUnhandled node type: {node['type']}") # DEBUG
    return []


def traverse_ast(node):
        global variables, taint_map, curr_contexts, curr_context_index

        if isinstance(node, dict) and 'type' in node:
            #print(node['type'], variables, taint_map) # DEBUG
            return copy.deepcopy(process_node(node)) # return a copy of the list to avoid modifying it in variable tracking

        elif isinstance(node, list):
            for child in node:  # each child is a line or a statement
                loop_size = len(curr_contexts) # avoid running with contexts created by child nodes for the same line
                for i in range(loop_size):
                    #print(f"\n\analysing line of {parent['type']} with context {i}") # DEBUG
                    variables, taint_map = curr_contexts[i]
                    curr_context_index = i
                    traverse_ast(child)


def handle_repeated_flows(flows):
    index = 1
    for i in range(len(flows)):
        if flows[i] is None: # already merged
            continue

        for j in range(i, len(flows)): # logic needs to merge with itself
            if flows[i] == flows[j]:
                flows[i].merge_sanitized_flows(flows[j])
                if j != i:
                    flows[j] = None # mark as repeated

        flows[i].set_index(index)
        index += 1

    all_flows = []
    for flow in flows:
        if flow is not None:
            all_flows.append(flow.to_dict())
    return all_flows


def detect_flows_for_pattern(ast_dict, pattern):
    # reassign pattern variables
    global vulnerability, sources, sanitizers, sinks, implicit, curr_contexts, flows, implicit_sources

    vulnerability = pattern["vulnerability"]
    sources = pattern["sources"]
    sanitizers = pattern["sanitizers"]
    sinks = pattern["sinks"]
    implicit = True if pattern["implicit"] == "yes" else False
    curr_contexts = [[[], {}]]
    flows = []
    implicit_sources = []

    traverse_ast(ast_dict)
    return handle_repeated_flows(flows)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python ./js_analyser.py <path_to_slice>.js <path_to_patterns>.json')
        exit()

    #print(f"\n\n\n\n\n\n\nAnalyzing {sys.argv[1]} with patterns from {sys.argv[2]}") # DEBUG

    with open(sys.argv[1], 'r') as f:
        fname = f.name.split('/')[-1].split('.')[0]
        program = f.read().strip()

    with open(sys.argv[2], 'r') as f:
        patterns = json.load(f)

    ast_dict = esprima.parseScript(program, loc = True).toDict()

    os.makedirs('./output', exist_ok=True)
    #with open(f'./output/{fname}.tree.json', 'w') as f:
    #    json.dump(ast_dict, f, indent=INDENT) # save AST tree for debug

    all_flows = []
    for pattern in patterns:
        all_flows.extend(detect_flows_for_pattern(ast_dict, pattern))

    with open(f'./output/{fname}.output.json', 'w') as f:
        json.dump(all_flows, f, indent=INDENT)

