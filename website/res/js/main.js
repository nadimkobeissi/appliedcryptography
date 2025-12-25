import {
	mobileInit
} from "./mobile.js";
import {
	menuInit
} from "./menu.js";
import {
	collapsibleInit
} from "./collapsible.js";
import {
	updatedInit
} from "./updated.js";
// import { calendarInit } from "./calendar.js"

document.addEventListener("DOMContentLoaded", () => {
	mobileInit();
	menuInit();
	collapsibleInit();
	updatedInit();
	// calendarInit()
});