"use strict";
const m03 = require("audit-large-m03");
const m04 = require("audit-large-m04");

module.exports = {
	name: "m05",
	info: function () {
		return { name: "m05", chain: ["m05", ...m03.info().chain, ...m04.info().chain] };
	},
};
