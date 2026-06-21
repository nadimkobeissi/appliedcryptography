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
	navspyInit
} from "./navspy.js";
document.addEventListener("DOMContentLoaded", () => {
	menuInit();
	collapsibleInit();
	updatedInit();
	calendarInit();
	navspyInit();
});