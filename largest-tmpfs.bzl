def _parser_test(ctx):
    test_runner = ctx.actions.declare_file(ctx.label.name)
    executable = ctx.attr.binary.files.to_list()[0]
    input_file = ctx.attr.input.files.to_list()[0]
    ctx.actions.write(
        content = """\
#!/bin/sh

set -eu

exec "{executable}" "{input}"
""".format(
    executable=executable.short_path,
    input=input_file.short_path),
        output = test_runner,
        is_executable = True)
    return [DefaultInfo(
        executable = test_runner,
        runfiles=ctx.runfiles([executable, input_file]))]

single_file_parser_test = rule(
    implementation = _parser_test,
    attrs = {
        "binary": attr.label(
            doc="""\
Binary of the test executable that takes the input file name as the
only parameter.""",
            cfg="host"),
        "input": attr.label(allow_single_file=True),
    },
    test = True,
)

def parser_test(name, binary, inputs, size="small"):
    for input_file in inputs:
        test_name = "%s-%s" % (name, input_file)
        single_file_parser_test(
            name = test_name,
            binary = binary,
            input = input_file,
            size = size,
        )

def _argument_test_impl(ctx):
    test_runner = ctx.actions.declare_file(ctx.label.name)
    executable = ctx.attr.binary.files.to_list()[0]
    ctx.actions.write(
        content = """\
#!/bin/sh

set -eu

exec "{executable}" "{arguments}"
""".format(
    executable=executable.short_path,
    arguments="\" \"".join(ctx.attr.arguments)),
        output = test_runner,
        is_executable = True)
    return [DefaultInfo(
        executable = test_runner,
        runfiles=ctx.runfiles([executable]))]

_argument_test = rule(
    implementation = _argument_test_impl,
    attrs = {
        "binary": attr.label(
            doc = "Binary of the largest-tmpfs executable",
            cfg = "host"),
        "arguments": attr.string_list(
            mandatory = True,
            allow_empty = False,
            doc = "Arguments to pass to the binary",
        ),
    },
    test = True
)

def argument_test(name, binary, arguments, size="small"):
    _argument_test(
        name = name,
        binary = binary,
        arguments = arguments,
        size = size,
    )
