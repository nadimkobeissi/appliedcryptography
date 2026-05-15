const ICS_URL = "res/data/calendar.ics"
const ICS_LIVE_URL = "https://user.fm/calendar/v1-d83f1fcd9819e56167c4beba63fcc806/AC%20Summer%202026.ics"

// ──────────────  Domain  ──────────────
const PS_TITLES = {
	1: "Provable Security Foundations",
	2: "Symmetric Cryptography",
	3: "Asymmetric Cryptography",
	4: "Secure Channel Protocols",
	5: "End-to-End Encrypted Cloud Storage",
	6: "High-Assurance Cryptography",
	7: "Post-Quantum Cryptography",
	8: "Zero-Knowledge Proofs",
}

const TOPIC_RE = /^Topic (\d+)\.(\d+):\s*(.+)$/
const PS_RE = /^Problem Set (\d+) Due$/
const EXAM_RE = /Exam$/

const webcalUrl = () => ICS_LIVE_URL.replace(/^https?:\/\//, "webcal://")
const googleAddUrl = () => `https://calendar.google.com/calendar/render?cid=${encodeURIComponent(webcalUrl())}`

export const classifyEvent = (raw) => {
	const summary = raw.summary || ""
	const topicMatch = summary.match(TOPIC_RE)
	if (topicMatch) {
		const [, part, idx, title] = topicMatch
		return {
			kind: "lecture",
			id: raw.uid,
			start: raw.dtstart,
			end: raw.dtend,
			topicNumber: `${part}.${idx}`,
			topicSlug: `${part}-${idx}`,
			title,
			hasQuiz: !(part === "1" && idx === "1"),
		}
	}
	const psMatch = summary.match(PS_RE)
	if (psMatch) {
		const n = +psMatch[1]
		return {
			kind: "problem-set",
			id: raw.uid,
			start: raw.dtstart,
			end: raw.dtend,
			number: n,
			title: PS_TITLES[n] || `Problem Set ${n}`,
		}
	}
	if (EXAM_RE.test(summary)) {
		return {
			kind: "exam",
			id: raw.uid,
			start: raw.dtstart,
			end: raw.dtend,
			title: summary,
			location: raw.location || null,
		}
	}
	console.warn("[calendar] unclassified event:", summary)
	return null
}

// ──────────────  ICS parser  ──────────────
// Tiny iCalendar subset: handles line unfolding and the three DTSTART/DTEND
// shapes used in this calendar (TZID-prefixed local, UTC with Z suffix, all-day).

const unfoldICS = (text) => {
	// RFC 5545: any line beginning with a space is a continuation of the
	// previous line. Normalize CRLF first.
	const lines = text.replace(/\r\n/g, "\n").split("\n")
	const out = []
	for (const line of lines) {
		if (line.startsWith(" ") || line.startsWith("\t")) {
			out[out.length - 1] += line.slice(1)
		} else {
			out.push(line)
		}
	}
	return out
}

const parseICSDateValue = (raw, params) => {
	const tzid = params.TZID || (raw.endsWith("Z") ? "UTC" : null)
	const allDay = !raw.includes("T")
	if (allDay) {
		const y = +raw.slice(0, 4),
			m = +raw.slice(4, 6),
			d = +raw.slice(6, 8)
		return {
			allDay: true,
			tz: null,
			instant: Date.UTC(y, m - 1, d),
			y,
			m,
			d,
		}
	}
	const y = +raw.slice(0, 4),
		mo = +raw.slice(4, 6),
		d = +raw.slice(6, 8)
	const h = +raw.slice(9, 11),
		mi = +raw.slice(11, 13),
		s = +raw.slice(13, 15)
	if (tzid === "UTC") {
		return {
			allDay: false,
			tz: "UTC",
			instant: Date.UTC(y, mo - 1, d, h, mi, s)
		}
	}
	if (tzid === "Asia/Beirut") {
		// Asia/Beirut is UTC+3 during summer DST (Mar last Sun → Oct last Sun).
		// The whole calendar runs Jun–Oct so all TZID-bearing events use +3
		// (the latest is the Oct 5 final exam, still before DST ends Oct 25).
		return {
			allDay: false,
			tz: "Asia/Beirut",
			instant: Date.UTC(y, mo - 1, d, h - 3, mi, s),
		}
	}
	return {
		allDay: false,
		tz: null,
		instant: new Date(y, mo - 1, d, h, mi, s).getTime()
	}
}

export const parseICS = (text) => {
	const lines = unfoldICS(text)
	const events = []
	let current = null
	for (const line of lines) {
		if (line === "BEGIN:VEVENT") {
			current = {};
			continue
		}
		if (line === "END:VEVENT") {
			if (current) events.push(current)
			current = null
			continue
		}
		if (!current) continue
		const colon = line.indexOf(":")
		if (colon < 0) continue
		const head = line.slice(0, colon)
		const value = line.slice(colon + 1)
		const [name, ...paramParts] = head.split(";")
		const params = {}
		for (const p of paramParts) {
			const eq = p.indexOf("=")
			if (eq > 0) params[p.slice(0, eq)] = p.slice(eq + 1)
		}
		if (name === "DTSTART" || name === "DTEND") {
			current[name.toLowerCase()] = parseICSDateValue(value, params)
		} else if (name === "SUMMARY" || name === "LOCATION" || name === "UID") {
			current[name.toLowerCase()] = value
		}
	}
	return events
}

// ──────────────  Formatters  ──────────────

const DAY_MS = 24 * 60 * 60 * 1000

const fmtDow = (instant, tz) =>
	new Intl.DateTimeFormat("en-US", {
		weekday: "short",
		timeZone: tz
	}).format(instant).toUpperCase()

const fmtDom = (instant, tz) =>
	new Intl.DateTimeFormat("en-US", {
		day: "numeric",
		timeZone: tz
	}).format(instant)

const fmtMon = (instant, tz) =>
	new Intl.DateTimeFormat("en-US", {
		month: "short",
		timeZone: tz
	}).format(instant)

const fmtTimeRange = (startInstant, endInstant, tz) => {
	const start = new Intl.DateTimeFormat("en-US", {
		hour: "numeric",
		minute: "2-digit",
		hour12: false,
		timeZone: tz
	}).format(startInstant)
	const end = new Intl.DateTimeFormat("en-US", {
		hour: "numeric",
		minute: "2-digit",
		hour12: false,
		timeZone: tz
	}).format(endInstant)
	return `${start}–${end}`
}

const tzShortLabel = (tz) => {
	if (tz === "Asia/Beirut") return "Beirut"
	if (tz === "UTC") return "UTC"
	const parts = new Intl.DateTimeFormat("en-US", {
		timeZoneName: "short",
		timeZone: tz
	}).formatToParts(Date.now())
	const tzPart = parts.find((p) => p.type === "timeZoneName")
	return tzPart ? tzPart.value : tz
}

// ISO week-of-semester: count Monday-starting weeks from the semester start.
const SEMESTER_START_UTC = Date.UTC(2026, 5, 8) // Mon Jun 8, 2026 (week 1 contains Tue Jun 9)
const weekIndex = (instant) => Math.max(1, Math.floor((instant - SEMESTER_START_UTC) / (7 * DAY_MS)) + 1)

const startOfWeekUTC = (instant) => {
	const d = new Date(instant)
	const dow = (d.getUTCDay() + 6) % 7 // 0 = Monday
	return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - dow)
}

const fmtWeekHeader = (instant, tz) => {
	const start = startOfWeekUTC(instant)
	const end = start + 6 * DAY_MS
	const idx = weekIndex(start)
	const startLabel = new Intl.DateTimeFormat("en-US", {
		month: "short",
		day: "numeric",
		timeZone: tz
	}).format(start)
	const endLabel = new Intl.DateTimeFormat("en-US", {
		month: "short",
		day: "numeric",
		timeZone: tz
	}).format(end)
	return `Week ${idx} — ${startLabel} to ${endLabel}`
}

const isSameDayUTC = (a, b) => {
	const da = new Date(a),
		db = new Date(b)
	return da.getUTCFullYear() === db.getUTCFullYear() &&
		da.getUTCMonth() === db.getUTCMonth() &&
		da.getUTCDate() === db.getUTCDate()
}

const todayInstant = () => {
	const now = new Date()
	return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())
}

// ──────────────  Renderers  ──────────────

const SEMESTER_END_UTC = Date.UTC(2026, 9, 5) // Mon Oct 5, 2026

const renderRibbon = (events) => {
	const today = todayInstant()
	const counts = events.reduce((acc, e) => {
		acc[e.kind] = (acc[e.kind] || 0) + 1;
		return acc
	}, {})
	const inRange = today >= SEMESTER_START_UTC && today <= SEMESTER_END_UTC
	const pct = inRange ? Math.min(100, Math.max(0,
		((today - SEMESTER_START_UTC) / (SEMESTER_END_UTC - SEMESTER_START_UTC)) * 100
	)) : null
	return `
		<span class="cal-ribbon-stat"><i class="icon ph-duotone ph-flag"></i><strong>Jun 9 – Oct 5, 2026</strong></span>
		<span class="cal-ribbon-stat"><i class="icon ph-duotone ph-calendar-dots"></i>17 weeks</span>
		<span class="cal-ribbon-stat"><i class="icon ph-duotone ph-chalkboard-teacher"></i>${counts.lecture || 0} lectures</span>
		<span class="cal-ribbon-stat"><i class="icon ph-duotone ph-check-square-offset"></i>${counts["problem-set"] || 0} problem sets</span>
		<span class="cal-ribbon-stat"><i class="icon ph-duotone ph-exam"></i>${counts.exam || 0} exams</span>
		${pct !== null ? `
			<div class="cal-ribbon-progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(pct)}" aria-label="Semester progress">
				<div class="cal-ribbon-progress-fill" style="width: ${pct.toFixed(1)}%"></div>
			</div>
		` : ""}
	`
}

const renderCaption = (state) => {
	const localTz = Intl.DateTimeFormat().resolvedOptions().timeZone
	const localOpt = localTz === "Asia/Beirut" ? "" :
		`<option value="local" ${state.tz === localTz ? "selected" : ""}>Your time (${localTz})</option>`
	return `
		<label class="cal-tz-label">Times shown in
			<select class="cal-tz" data-action="set-tz" aria-label="Timezone">
				<option value="beirut" ${state.tz === "Asia/Beirut" ? "selected" : ""}>Beirut (UTC+3)</option>
				${localOpt}
				<option value="utc" ${state.tz === "UTC" ? "selected" : ""}>UTC</option>
			</select>
		</label>
		<span class="cal-legend">
			<span class="cal-legend-item"><span class="cal-legend-dot" data-kind="lecture"></span>Lecture</span>
			<span class="cal-legend-item"><span class="cal-legend-dot" data-kind="problem-set"></span>Problem Set</span>
			<span class="cal-legend-item"><span class="cal-legend-dot" data-kind="exam"></span>Exam</span>
		</span>
	`
}

const renderToolbar = (state) => `
	<div class="cal-tabs" role="tablist" aria-label="Calendar view">
		<button class="cal-tab" role="tab" data-action="set-view" data-view="month"
		        aria-selected="${state.view === "month"}">
			<i class="icon ph-duotone ph-calendar"></i>Month
		</button>
		<button class="cal-tab" role="tab" data-action="set-view" data-view="agenda"
		        aria-selected="${state.view === "agenda"}">
			<i class="icon ph-duotone ph-list-bullets"></i>Agenda
		</button>
	</div>
	<div class="cal-filters" role="group" aria-label="Filter events">
		<button class="cal-filter" data-action="toggle-filter" data-kind="lecture"
		        aria-pressed="${state.filters.includes("lecture")}">
			<span class="cal-legend-dot" data-kind="lecture" aria-hidden="true"></span>Lectures
		</button>
		<button class="cal-filter" data-action="toggle-filter" data-kind="problem-set"
		        aria-pressed="${state.filters.includes("problem-set")}">
			<span class="cal-legend-dot" data-kind="problem-set" aria-hidden="true"></span>Problem Sets
		</button>
		<button class="cal-filter" data-action="toggle-filter" data-kind="exam"
		        aria-pressed="${state.filters.includes("exam")}">
			<span class="cal-legend-dot" data-kind="exam" aria-hidden="true"></span>Exams
		</button>
	</div>
	<div class="cal-subscribe">
		<a class="cal-subscribe-primary" href="${webcalUrl()}"
		   title="Subscribe in Apple Calendar / Outlook / Fantastical">
			<i class="icon ph-duotone ph-rss"></i>Subscribe
		</a>
		<a href="${ICS_URL}" download="AC-Summer-2026.ics"
		   title="Download .ics file">
			<i class="icon ph-duotone ph-download-simple"></i>.ics
		</a>
		<a href="${googleAddUrl()}" target="_blank" rel="noopener"
		   title="Add to Google Calendar">
			<i class="icon ph-duotone ph-google-logo"></i>Google
		</a>
	</div>
`

const renderEventCard = (event, state) => {
	const tz = state.tz
	const startInst = event.start.instant
	const dow = fmtDow(startInst, tz)
	const dom = fmtDom(startInst, tz)
	const mon = fmtMon(startInst, tz)
	const isToday = isSameDayUTC(startInst, todayInstant())
	const isAllDay = event.start.allDay
	const time = isAllDay ?
		"All day" :
		`${fmtTimeRange(startInst, event.end.instant, tz)} ${tzShortLabel(tz)}`

	let kindLabel = "Lecture",
		kindIcon = "ph-chalkboard-teacher"
	if (event.kind === "problem-set") {
		kindLabel = "Problem Set";
		kindIcon = "ph-check-square-offset"
	}
	if (event.kind === "exam") {
		kindLabel = "Exam";
		kindIcon = "ph-exam"
	}

	let title = "",
		sub = "",
		actions = ""
	if (event.kind === "lecture") {
		title = `<a href="slides/#${event.topicSlug}">Topic ${event.topicNumber} · ${event.title}</a>`
		const slides = `<a class="cal-event-btn" data-primary="true" href="slides/#${event.topicSlug}"><i class="icon ph-duotone ph-projector-screen"></i>Slides</a>`
		const quiz = event.hasQuiz ?
			`<a class="cal-event-btn" href="quiz/#${event.topicSlug}"><i class="icon ph-duotone ph-seal-question"></i>Quiz</a>` :
			""
		actions = `${slides}${quiz}`
	} else if (event.kind === "problem-set") {
		title = `<a href="problem-set/#${event.number}">Problem Set ${event.number} · ${event.title}</a>`
		actions = `<a class="cal-event-btn" data-primary="true" href="problem-set/#${event.number}"><i class="icon ph-duotone ph-check-square-offset"></i>View</a>`
	} else {
		title = event.title
		if (event.location) sub = `<p class="cal-event-sub"><i class="icon ph-duotone ph-map-pin"></i>${event.location}</p>`
	}

	return `
		<article class="cal-event" data-kind="${event.kind}" data-today="${isToday}">
			<div class="cal-event-date">
				<span class="cal-event-dow">${dow}</span>
				<span class="cal-event-day">${dom}</span>
				<span class="cal-event-mon">${mon}</span>
			</div>
			<div class="cal-event-body">
				<div class="cal-event-meta">
					<span class="cal-event-kind" data-kind="${event.kind}"><i class="icon ph-duotone ${kindIcon}"></i>${kindLabel}</span>
					<span class="cal-event-time">${time}</span>
					${isToday ? `<span class="cal-event-today">Today</span>` : ""}
				</div>
				<h4 class="cal-event-title">${title}</h4>
				${sub}
			</div>
			<div class="cal-event-actions">${actions}</div>
		</article>
	`
}

const MONTHS = ["June 2026", "July 2026", "August 2026", "September 2026", "October 2026"]
const MONTH_KEYS = ["2026-06", "2026-07", "2026-08", "2026-09", "2026-10"]

const monthKeyToParts = (key) => {
	const [y, m] = key.split("-").map(Number)
	return {
		y,
		m: m - 1
	}
}

const monthLabel = (key) => MONTHS[MONTH_KEYS.indexOf(key)] || key

const todayMonthKey = () => {
	const now = new Date()
	const k = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`
	return MONTH_KEYS.includes(k) ? k : "2026-06"
}

const eventMonthKey = (event, tz) => {
	const fmt = new Intl.DateTimeFormat("en-CA", {
		timeZone: tz,
		year: "numeric",
		month: "2-digit",
		day: "2-digit"
	})
	return fmt.format(event.start.instant).slice(0, 7)
}

// Tiny HTML builder used by the month-grid / day-panel renderers so the
// resulting markup is built from JS function calls instead of nested
// template literals — js-beautify mangles closing tags inside templates
// that sit adjacent to ${...} interpolations.
const h = (tag, attrs, ...children) => {
	const attrStr = attrs
		? Object.entries(attrs)
			.filter(([, v]) => v !== null && v !== undefined && v !== false)
			.map(([k, v]) => ` ${k}="${String(v).replace(/"/g, "&quot;")}"`)
			.join("")
		: ""
	const inner = children
		.filter((c) => c !== null && c !== undefined && c !== false && c !== "")
		.join("")
	return `<${tag}${attrStr}>${inner}</${tag}>`
}

const renderMonthHeader = (state) => {
	const idx = MONTH_KEYS.indexOf(state.month)
	return h("h3", { class: "cal-month-title" }, monthLabel(state.month)) +
		h("div", { class: "cal-month-nav" },
			h("button", {
				"data-action": "month-prev",
				"aria-label": "Previous month",
				disabled: idx <= 0 ? "" : null,
			}, "‹"),
			h("button", {
				"data-action": "month-next",
				"aria-label": "Next month",
				disabled: idx >= MONTH_KEYS.length - 1 ? "" : null,
			}, "›"),
		)
}

const buildMonthCells = (key) => {
	const {
		y,
		m
	} = monthKeyToParts(key)
	const first = new Date(Date.UTC(y, m, 1))
	const leading = (first.getUTCDay() + 6) % 7 // 0 = Monday
	const gridStart = Date.UTC(y, m, 1 - leading)
	const cells = []
	for (let i = 0; i < 42; i++) {
		const d = new Date(gridStart + i * DAY_MS)
		cells.push({
			instant: gridStart + i * DAY_MS,
			day: d.getUTCDate(),
			outside: d.getUTCMonth() !== m,
		})
	}
	return cells
}

const eventsOnDay = (events, dayInstant, tz) => {
	const fmt = new Intl.DateTimeFormat("en-CA", {
		timeZone: tz,
		year: "numeric",
		month: "2-digit",
		day: "numeric"
	})
	const target = fmt.format(dayInstant)
	return events.filter((e) => fmt.format(e.start.instant) === target)
}

const dayChipLabel = (event) => {
	if (event.kind === "lecture") return `${event.topicNumber}`
	if (event.kind === "problem-set") return `PS${event.number}`
	if (event.kind === "exam") return event.title === "Final Exam" ? "Final" : "Mid"
	return ""
}

const renderMonthGrid = (events, state) => {
	const visible = events.filter((e) => state.filters.includes(e.kind))
	const cells = buildMonthCells(state.month)
	const today = todayInstant()
	const dayHeaders = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

	const renderCell = (cell) => {
		const dayEvents = cell.outside ? [] : eventsOnDay(visible, cell.instant, state.tz)
		const shown = dayEvents.slice(0, 3)
		const overflow = dayEvents.length - shown.length
		const isToday = isSameDayUTC(cell.instant, today)
		const isSelected = state.day === cell.instant
		const dateLabel = new Intl.DateTimeFormat("en-US", {
			weekday: "long", year: "numeric", month: "long", day: "numeric", timeZone: state.tz,
		}).format(cell.instant)
		const chips = shown.map((e) =>
			h("span", { class: "cal-day-chip", "data-kind": e.kind }, dayChipLabel(e))
		)
		const moreChip = overflow > 0
			? h("span", { class: "cal-day-more" }, `+${overflow} more`)
			: ""
		return h("td", {
			role: "gridcell",
			"data-outside": String(cell.outside),
			"data-today": String(isToday),
			"data-selected": String(isSelected),
			"data-action": "select-day",
			"data-instant": cell.instant,
			"aria-selected": String(isSelected),
			"aria-label": `${dateLabel}, ${dayEvents.length} event${dayEvents.length === 1 ? "" : "s"}`,
			tabindex: isSelected ? "0" : "-1",
		},
			h("span", { class: "cal-day-num" }, cell.day),
			h("div", { class: "cal-day-chips" }, ...chips, moreChip),
		)
	}

	const headerRow = h("tr", null,
		...dayHeaders.map((label) => h("th", { scope: "col" }, label))
	)

	const bodyRows = [0, 1, 2, 3, 4, 5].map((rowIdx) =>
		h("tr", null, ...cells.slice(rowIdx * 7, rowIdx * 7 + 7).map(renderCell))
	)

	return h("div", { class: "cal-month-grid", role: "grid", "aria-label": monthLabel(state.month) },
		h("div", { class: "cal-month-header" }, renderMonthHeader(state)),
		h("table", { class: "cal-month-table" },
			h("thead", null, headerRow),
			h("tbody", null, ...bodyRows),
		),
	)
}

const renderDayPanel = (events, state) => {
	const visible = events.filter((e) => state.filters.includes(e.kind))
	if (!state.day) {
		return h("aside", { class: "cal-day-panel" },
			h("p", { class: "cal-day-panel-empty" }, "Select a day to see its events."),
		)
	}
	const dayEvents = eventsOnDay(visible, state.day, state.tz)
	const heading = new Intl.DateTimeFormat("en-US", {
		weekday: "long", month: "long", day: "numeric", timeZone: state.tz,
	}).format(state.day)
	const body = dayEvents.length === 0
		? h("p", { class: "cal-day-panel-empty" }, "No events on this day.")
		: dayEvents.map((e) => renderEventCard(e, state)).join("")
	return h("aside", { class: "cal-day-panel" },
		h("h3", { class: "cal-day-panel-title" }, heading),
		body,
	)
}

const renderMonth = (events, state) => `
	<div class="cal-month">
		${renderMonthGrid(events, state)}
		${renderDayPanel(events, state)}
	</div>
`

const renderAgenda = (events, state) => {
	const monthEvents = events
		.filter((e) => state.filters.includes(e.kind))
		.filter((e) => eventMonthKey(e, state.tz) === state.month)
	const header = `<div class="cal-agenda-header">${renderMonthHeader(state)}</div>`
	if (monthEvents.length === 0) {
		return `${header}<div class="cal-empty"><i class="icon ph-duotone ph-calendar-x"></i>No events match these filters this month.</div>`
	}
	const groups = new Map()
	for (const e of monthEvents) {
		const key = startOfWeekUTC(e.start.instant)
		if (!groups.has(key)) groups.set(key, [])
		groups.get(key).push(e)
	}
	const sorted = [...groups.entries()].sort(([a], [b]) => a - b)
	return `
		${header}
		<ol class="cal-agenda" aria-label="${monthLabel(state.month)} events">
			${sorted.map(([weekStart, weekEvents]) => `
				<li class="cal-week">
					<h3 class="cal-week-header">${fmtWeekHeader(weekStart, state.tz)}</h3>
					${weekEvents.map((e) => renderEventCard(e, state)).join("")}
				</li>
			`).join("")}
		</ol>
	`
}

// ──────────────  URL state  ──────────────

const VALID_KINDS = ["lecture", "problem-set", "exam"]
const KIND_TO_KEY = {
	lecture: "lec",
	"problem-set": "ps",
	exam: "exam"
}
const KEY_TO_KIND = {
	lec: "lecture",
	ps: "problem-set",
	exam: "exam"
}

export const serializeState = (state) => {
	const parts = []
	if (state.view !== "month") parts.push(`view=${state.view}`)
	if (state.month !== todayMonthKey()) parts.push(`m=${state.month}`)
	if (state.day) {
		const d = new Date(state.day)
		parts.push(`d=${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(d.getUTCDate()).padStart(2, "0")}`)
	}
	const filtersDefault = VALID_KINDS.every((k) => state.filters.includes(k))
	if (!filtersDefault) {
		parts.push(`filters=${state.filters.map((k) => KIND_TO_KEY[k]).join(",")}`)
	}
	if (state.tz !== "Asia/Beirut") parts.push(`tz=${state.tz === "UTC" ? "utc" : "local"}`)
	return parts.length ? `calendar?${parts.join("&")}` : "calendar"
}

export const deserializeState = (hash, defaults) => {
	const state = {
		...defaults
	}
	if (!hash || !hash.startsWith("#calendar")) return state
	const queryIdx = hash.indexOf("?")
	if (queryIdx < 0) return state
	const params = new URLSearchParams(hash.slice(queryIdx + 1))
	if (params.has("view")) {
		const v = params.get("view")
		if (v === "agenda" || v === "month") state.view = v
	}
	if (params.has("m")) {
		const m = params.get("m")
		if (MONTH_KEYS.includes(m)) state.month = m
	}
	if (params.has("d")) {
		const d = params.get("d")
		const match = d.match(/^(\d{4})-(\d{2})-(\d{2})$/)
		if (match) state.day = Date.UTC(+match[1], +match[2] - 1, +match[3])
	}
	if (params.has("filters")) {
		const keys = params.get("filters").split(",").filter(Boolean)
		const kinds = keys.map((k) => KEY_TO_KIND[k]).filter(Boolean)
		if (kinds.length > 0) state.filters = kinds
	}
	if (params.has("tz")) {
		const tz = params.get("tz")
		if (tz === "utc") state.tz = "UTC"
		else if (tz === "local") state.tz = Intl.DateTimeFormat().resolvedOptions().timeZone
	}
	return state
}

export const calendarInit = async () => {
	const section = document.getElementById("calendar")
	if (!section) return
	const viewHost = section.querySelector("[data-cal-view]")
	viewHost.innerHTML = `<p class="text-muted">Loading calendar…</p>`

	try {
		const res = await fetch(ICS_URL, {
			cache: "no-cache"
		})
		if (!res.ok) throw new Error(`HTTP ${res.status}`)
		const text = await res.text()
		const events = parseICS(text)
			.map(classifyEvent)
			.filter(Boolean)
			.sort((a, b) => a.start.instant - b.start.instant)
		const defaults = {
			view: "month",
			filters: ["lecture", "problem-set", "exam"],
			month: todayMonthKey(),
			day: null,
			tz: "Asia/Beirut",
		}
		const state = deserializeState(window.location.hash, defaults)
		// On very narrow viewports, month view is hidden via CSS.
		// Force agenda on first paint so something is always visible.
		if (window.matchMedia("(max-width: 576px)").matches) {
			state.view = "agenda"
		}
		// In month view, default the selected day to the non-empty day
		// closest to today (preferring the upcoming one on ties), so the
		// side panel always has content to show.
		if (state.view === "month" && !state.day) {
			const eventDayInstant = (event) => {
				const fmt = new Intl.DateTimeFormat("en-CA", {
					timeZone: state.tz, year: "numeric", month: "2-digit", day: "2-digit",
				})
				const [y, m, d] = fmt.format(event.start.instant).split("-").map(Number)
				return Date.UTC(y, m - 1, d)
			}
			const t = todayInstant()
			const candidates = events
				.filter((e) => state.filters.includes(e.kind))
				.map((e) => {
					const dayInst = eventDayInstant(e)
					return { dayInst, diff: Math.abs(dayInst - t), future: dayInst >= t }
				})
			candidates.sort((a, b) => a.diff - b.diff || Number(b.future) - Number(a.future))
			const best = candidates[0]
			if (best) {
				state.day = best.dayInst
				const d = new Date(best.dayInst)
				state.month = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`
			}
		}
		const ribbonHost = section.querySelector("[data-cal-ribbon]")
		ribbonHost.innerHTML = renderRibbon(events)
		ribbonHost.hidden = false
		const toolbarHost = section.querySelector("[data-cal-toolbar]")
		const captionHost = section.querySelector("[data-cal-caption]")

		const rerender = () => {
			toolbarHost.innerHTML = renderToolbar(state)
			viewHost.innerHTML = state.view === "agenda" ? renderAgenda(events, state) : renderMonth(events, state)
			captionHost.innerHTML = renderCaption(state)
			const next = `#${serializeState(state)}`
			if (window.location.hash !== next) history.replaceState(null, "", next)
		}

		rerender()

		section.addEventListener("click", (e) => {
			const target = e.target.closest("[data-action]")
			if (!target) return
			const action = target.dataset.action
			if (action === "toggle-filter") {
				const kind = target.dataset.kind
				state.filters = state.filters.includes(kind) ?
					state.filters.filter((k) => k !== kind) :
					[...state.filters, kind]
				rerender()
			} else if (action === "set-view") {
				state.view = target.dataset.view
				if (state.view === "month" && !state.day) {
					const t = todayInstant()
					const inRange = events.some((ev) => isSameDayUTC(ev.start.instant, t))
					state.day = inRange ? t : events[0]?.start.instant ?? null
					if (state.day) {
						const d = new Date(state.day)
						state.month = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`
					}
				}
				rerender()
			} else if (action === "month-prev" || action === "month-next") {
				const i = MONTH_KEYS.indexOf(state.month)
				const ni = action === "month-prev" ? i - 1 : i + 1
				if (ni >= 0 && ni < MONTH_KEYS.length) state.month = MONTH_KEYS[ni]
				rerender()
			} else if (action === "select-day") {
				if (target.dataset.outside === "true") return
				state.day = Number(target.dataset.instant)
				rerender()
			}
		})

		section.addEventListener("change", (e) => {
			const target = e.target.closest("[data-action='set-tz']")
			if (!target) return
			const val = target.value
			if (val === "beirut") state.tz = "Asia/Beirut"
			else if (val === "utc") state.tz = "UTC"
			else if (val === "local") state.tz = Intl.DateTimeFormat().resolvedOptions().timeZone
			rerender()
		})

		window.addEventListener("hashchange", () => {
			const next = deserializeState(window.location.hash, defaults)
			Object.assign(state, next)
			rerender()
		})
	} catch (err) {
		console.error("[calendar] fetch failed", err)
		viewHost.innerHTML = `<div class="cal-error">Couldn't load the calendar. <a href="${ICS_LIVE_URL}">View it on user.fm →</a></div>`
	}
}