"use strict";
// Required as `audit-fixture-self-ref-pkg/lib/util` from siblings.
exports.upper = function (s) {
	return String(s).toUpperCase();
};
exports.kind = "self-ref-util";
