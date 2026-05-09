"use strict";
const a = require("audit-cycle-a");

exports.helloFromB = function () {
	return "hello-from-b";
};

exports.bTouchesA = function () {
	return a.helloFromA() + "/from-b";
};
