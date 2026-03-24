import {
	Calendar
} from "https://cdn.skypack.dev/@fullcalendar/core"
import listPlugin from "https://cdn.skypack.dev/@fullcalendar/list"
import iCalendarPlugin from "https://cdn.skypack.dev/@fullcalendar/icalendar"

const calendarIcsUrl = "https://calendar.google.com/calendar/ical/classroom101341617761136608909%40group.calendar.google.com/public/basic.ics"

export const calendarInit = () => {
	var calendarEl = document.getElementById("calendar-frame")

	const today = new Date()
	const june8 = new Date(today.getFullYear(), 5, 8)
	const initialDate = today < june8 ? june8 : today

	var calendar = new Calendar(calendarEl, {
		initialView: "listWeek",
		initialDate: initialDate,
		plugins: [listPlugin, iCalendarPlugin],
		events: {
			url: calendarIcsUrl,
			format: "ics",
		},
		eventColor: "green",
		height: 700,
		eventContent: function(arg) {
			let arrayOfDomNodes = []

			let titleEl = document.createElement("div")
			titleEl.classList.add("fc-event-title")
			titleEl.innerText = arg.event.title
			arrayOfDomNodes.push(titleEl)

			if (arg.event.extendedProps.location) {
				let locationEl = document.createElement("div")
				locationEl.classList.add("fc-event-location")

				let locationLabel = document.createElement("strong")
				locationLabel.textContent = "Location: "
				locationEl.appendChild(locationLabel)
				let locationText = document.createTextNode(arg.event.extendedProps.location)
				locationEl.appendChild(locationText)
				arrayOfDomNodes.push(locationEl)
			}

			if (arg.event.extendedProps.description) {
				let notesEl = document.createElement("div")
				notesEl.classList.add("fc-event-notes")
				let notesLabel = document.createElement("strong")
				notesLabel.textContent = "Notes: "
				notesEl.appendChild(notesLabel)
				let notesText = document.createTextNode(arg.event.extendedProps.description)
				notesEl.appendChild(notesText)
				arrayOfDomNodes.push(notesEl)
			}

			return {
				domNodes: arrayOfDomNodes
			}
		},
	})
	calendar.render()
}