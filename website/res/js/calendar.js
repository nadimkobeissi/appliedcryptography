import { Calendar } from "@fullcalendar/core"
import listPlugin from "@fullcalendar/list"
import iCalendarPlugin from "@fullcalendar/icalendar"

export const calendarInit = () => {
	var calendarEl = document.getElementById("calendar-frame")
	var calendar = new Calendar(calendarEl, {
		initialView: "listWeek",
		plugins: [listPlugin, iCalendarPlugin],
		events: {
			url: "https://user.fm/calendar/v1-e730b6a1ee5ac413a9972eed73a9da92/Applied%20Cryptography.ics",
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

			if (arg.event.url) {
				let urlEl = document.createElement("div")
				urlEl.classList.add("fc-event-url")
				let urlLabel = document.createElement("strong")
				urlLabel.textContent = "URL: "
				urlEl.appendChild(urlLabel)
				let urlLink = document.createElement("a")
				urlLink.href = arg.event.url
				urlLink.textContent = arg.event.url
				urlLink.target = "_blank"
				urlEl.appendChild(urlLink)
				arrayOfDomNodes.push(urlEl)
			}

			return { domNodes: arrayOfDomNodes }
		},
	})
	calendar.render()
}
