import { menuInit } from "./menu.js"
import { collapsibleInit } from "./collapsible.js"
import { updatedInit } from "./updated.js"
import { countdownInit } from "./countdown.js"

document.addEventListener("DOMContentLoaded", () => {
	menuInit()
	collapsibleInit()
	updatedInit()
	countdownInit()
})
