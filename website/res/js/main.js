import {
	menuInit
} from "./menu.js";
import {
	collapsibleInit
} from "./collapsible.js";
import {
	updatedInit
} from "./updated.js";
import {
	calendarInit
} from "./calendar.js";
import {
	revealInit
} from "./reveal.js";
import {
	navspyInit
} from "./navspy.js";
document.addEventListener("DOMContentLoaded", () => {
	menuInit();
	collapsibleInit();
	updatedInit();
	calendarInit();
	revealInit();
	navspyInit();
});
