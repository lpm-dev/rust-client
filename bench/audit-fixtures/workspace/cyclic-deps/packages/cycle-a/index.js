"use strict";
// Cyclic require: cycle-a loads cycle-b at module init. Whichever side
// is required first sees the other as a still-loading module — its
// `module.exports` is whatever it has assigned so far (initially `{}`).
// We export plain functions that close over `b`; their bodies run
// after both modules have completed, so by call time `b` has its
// final exports object.
const b = require("audit-cycle-b");

exports.helloFromA = function () {
	return "hello-from-a";
};

exports.aTouchesB = function () {
	return b.helloFromB() + "/from-a";
};
