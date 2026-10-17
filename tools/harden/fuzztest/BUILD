# tools/harden/fuzztest — see lab.sh fuzztest-{userspace,local,remote,ledger}.

load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

cc_library(
    name = "kcov_feedback",
    testonly = True,
    srcs = ["kcov_feedback.cc"],
    hdrs = ["kcov_feedback.h"],
    # Pull in FuzzTest so FUZZTEST_USE_CENTIPEDE (a `defines` of its Centipede
    # adaptor) reaches this file in --config=fuzztest-experimental builds.
    deps = ["@com_google_fuzztest//fuzztest"],
    # Keep the __centipede_extra_features array even though nothing refers
    # to it by name.
    alwayslink = True,
)

[cc_test(
    name = name,
    srcs = [name + ".cc"],
    deps = [
        ":kcov_feedback",
        "@com_google_fuzztest//fuzztest",
        "@com_google_fuzztest//fuzztest:fuzztest_gtest_main",
        "@googletest//:gtest",
    ],
) for name in [
    "userspace_fuzztest",
    "harden_fuzztest",
    "ledger_fuzztest",
]]
