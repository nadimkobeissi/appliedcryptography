import { menuInit } from "./menu.js"
import { collapsibleInit } from "./collapsible.js"
import { updatedInit } from "./updated.js"
import { calendarInit } from "./calendar.js"
import { mobileInit } from "./mobile.js"

document.addEventListener("DOMContentLoaded", () => {
	menuInit()
	collapsibleInit()
	updatedInit()
	calendarInit()
	mobileInit()
})
