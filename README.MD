# here is another ReDoS detector, for python

## first time setup

### upfront notice

Firstly, I recommend Ubuntu or WSL as the test environment, although it's possible to get up and running with MacOS too, it may require building LLVM and atheris from source. 

Now install [atheris](https://github.com/google/atheris/blob/master/README.md#installation-instructions).

Now compile, using the instructions from the [native_etension_fuzzing tutorial](https://github.com/google/atheris/blob/master/native_extension_fuzzing.md), the modified version of regex at [github.com/micsthepick/regex-mrab-bench](https://github.com/micsthepick/regex-mrab-bench). This version adds the capability of tracking stack max usage and backtracking counts.

### usage

change the regex in fuzzer.py to your liking, and use create_examples as inspiration for writing your own, or just let the fuzzer discover cases for itself. Start fuzzing by copying the desired examples from `base_examples/` to `examples/`, and running `./do_fuzz.sh`.