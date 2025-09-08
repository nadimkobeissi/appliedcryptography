import { Calendar } from "https://cdn.skypack.dev/@fullcalendar/core"
import listPlugin from "https://cdn.skypack.dev/@fullcalendar/list"
import iCalendarPlugin from "https://cdn.skypack.dev/@fullcalendar/icalendar@6.1.18"

const calendarIcsUrl = "https://user.fm/calendar/v1-e730b6a1ee5ac413a9972eed73a9da92/Applied%20Cryptography.ics"

export const calendarInit = () => {
	var calendarEl = document.getElementById("calendar-frame")
	var calendar = new Calendar(calendarEl, {
		initialView: "listWeek",
		plugins: [listPlugin, iCalendarPlugin],
		events: {
			url: calendarIcsUrl,
			format: "ics",
		},
		eventColor: "green",
		height: 700,
		eventContent: function (arg) {
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

			return { domNodes: arrayOfDomNodes }
		},
	})
	calendar.render()
}
