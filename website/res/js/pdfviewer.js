import * as pdfjsLib from "https://cdn.jsdelivr.net/npm/pdfjs-dist@6.1.200/build/pdf.min.mjs"

pdfjsLib.GlobalWorkerOptions.workerSrc = `https://cdn.jsdelivr.net/npm/pdfjs-dist@6.1.200/build/pdf.worker.min.mjs`

const SCALE_STEP = 0.25
const MAX_PIXEL_RATIO = 2
const RENDER_MARGIN_PX = 800
const FIND_DEBOUNCE_MS = 200
const PHOSPHOR_HREF = `/res/fonts/phosphor/phosphor.css`

const VIEWER_CSS = `
#toolbar {
	display: flex;
	align-items: center;
	justify-content: space-between;
	padding: 0 16px;
	height: 46px;
	background: #16201a;
	font-family: "Inria Sans", sans-serif;
	color: #c2cfb6;
	flex-shrink: 0;
	border-bottom: 1px solid #29362a;
	user-select: none;
	-webkit-user-select: none;
}
#toolbar-nav {
	display: flex;
	align-items: center;
	gap: 8px;
	min-width: 0;
	overflow: hidden;
}
#toolbar-nav a {
	color: #a4e486;
	text-decoration: none;
	font-weight: 700;
	font-size: 14px;
	white-space: nowrap;
	transition: color 0.2s ease;
}
#toolbar-nav a:hover { color: #e6b87a; }
#toolbar-sep { color: #485440; font-size: 13px; flex-shrink: 0; }
#toolbar-badge {
	font-family: "JetBrains Mono", monospace;
	font-size: 0.75rem;
	color: #e6b87a;
	background: #11180e;
	padding: 3px 10px;
	border-radius: 50px;
	white-space: nowrap;
	border: 1px solid rgba(212, 164, 100, 0.28);
	flex-shrink: 0;
}
#toolbar-controls {
	display: flex;
	align-items: center;
	gap: 6px;
	flex-shrink: 0;
}
#page-info {
	font-family: "JetBrains Mono", monospace;
	font-size: 0.75rem;
	white-space: nowrap;
	color: #8b9881;
	display: inline-flex;
	align-items: center;
	gap: 2px;
}
#page-current {
	cursor: pointer;
	padding: 2px 5px;
	border-radius: 3px;
	color: #c2cfb6;
	transition: background 0.15s ease;
	outline: none;
}
#page-current:hover, #page-current:focus { background: #1c2820; }
input#page-current {
	background: #11180e;
	border: 1px solid #e6b87a;
	border-radius: 3px;
	color: #c2cfb6;
	font-family: "JetBrains Mono", monospace;
	font-size: 0.75rem;
	padding: 1px 4px;
	text-align: center;
	cursor: text;
}
#page-sep { padding: 0 2px; }
#toolbar-controls .tb-btn {
	background: none;
	color: #c2cfb6;
	border: 1px solid #29362a;
	border-radius: 4px;
	width: 28px;
	height: 28px;
	cursor: pointer;
	display: inline-flex;
	align-items: center;
	justify-content: center;
	padding: 0;
	line-height: 1;
	transition: all 0.15s ease;
}
#toolbar-controls .tb-btn:hover {
	background: #1c2820;
	color: #e6b87a;
	border-color: #e6b87a;
}
#toolbar-controls .tb-btn.active {
	background: #1c2820;
	color: #e6b87a;
	border-color: #e6b87a;
}
#toolbar-controls .tb-btn .icon { font-size: 16px; line-height: 1; }
#zoom-level {
	font-family: "JetBrains Mono", monospace;
	font-size: 0.7rem;
	min-width: 36px;
	text-align: center;
	color: #8b9881;
}
#download {
	color: #16201a;
	text-decoration: none;
	font-family: "Inria Sans", sans-serif;
	font-size: 0.8rem;
	font-weight: 700;
	padding: 4px 10px;
	background: #4a8e3a;
	border-radius: 8px;
	white-space: nowrap;
	transition: all 0.2s ease;
	display: inline-flex;
	align-items: center;
	gap: 6px;
}
#download:hover { background: #a4e486; }
#download .icon { font-size: 14px; }
#find-bar {
	display: flex;
	align-items: center;
	gap: 8px;
	padding: 6px 12px;
	background: #16201a;
	border-bottom: 1px solid #29362a;
	flex-shrink: 0;
}
#find-bar[hidden] { display: none; }
#find-bar .find-icon { color: #e6b87a; display: inline-flex; }
#find-bar .find-icon .icon { font-size: 16px; }
#find-input {
	flex: 1;
	min-width: 0;
	max-width: 420px;
	background: #11180e;
	border: 1px solid #29362a;
	border-radius: 4px;
	color: #c2cfb6;
	font-family: "Inria Sans", sans-serif;
	font-size: 14px;
	padding: 4px 10px;
	outline: none;
}
#find-input:focus { border-color: #e6b87a; }
#find-counter {
	font-family: "JetBrains Mono", monospace;
	font-size: 0.75rem;
	color: #8b9881;
	white-space: nowrap;
	min-width: 70px;
	text-align: right;
}
#find-bar .tb-btn {
	background: none;
	color: #c2cfb6;
	border: 1px solid #29362a;
	border-radius: 4px;
	width: 28px;
	height: 28px;
	cursor: pointer;
	display: inline-flex;
	align-items: center;
	justify-content: center;
	padding: 0;
	transition: all 0.15s ease;
}
#find-bar .tb-btn:hover {
	background: #1c2820;
	color: #e6b87a;
	border-color: #e6b87a;
}
#find-bar .tb-btn .icon { font-size: 14px; }
#help-overlay {
	position: fixed;
	inset: 0;
	background: rgba(8, 18, 4, 0.75);
	z-index: 1000;
	display: flex;
	align-items: center;
	justify-content: center;
}
#help-overlay[hidden] { display: none; }
#help-card {
	background: #16201a;
	border: 2px solid #29362a;
	border-radius: 12px;
	color: #c2cfb6;
	font-family: "Inria Sans", sans-serif;
	width: min(92vw, 580px);
	max-height: 86vh;
	overflow: auto;
	box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6);
}
#help-header {
	display: flex;
	align-items: center;
	justify-content: space-between;
	padding: 14px 18px;
	border-bottom: 1px solid #29362a;
	font-weight: 700;
	font-size: 15px;
	color: #e6b87a;
}
#help-header .tb-btn {
	background: none;
	color: #c2cfb6;
	border: 1px solid #29362a;
	border-radius: 4px;
	width: 28px;
	height: 28px;
	cursor: pointer;
	display: inline-flex;
	align-items: center;
	justify-content: center;
	padding: 0;
}
#help-header .tb-btn:hover {
	background: #1c2820;
	color: #e6b87a;
	border-color: #e6b87a;
}
#help-content { padding: 14px 18px 18px; font-size: 13.5px; line-height: 1.5; }
#help-content h4 {
	color: #e6b87a;
	font-size: 11px;
	text-transform: uppercase;
	letter-spacing: 0.06em;
	margin: 16px 0 6px;
	font-weight: 700;
}
#help-content h4:first-child { margin-top: 0; }
#help-content table { width: 100%; border-collapse: collapse; }
#help-content td { padding: 4px 0; vertical-align: top; }
#help-content td:first-child {
	color: #8b9881;
	white-space: nowrap;
	padding-right: 16px;
	width: 46%;
}
#help-content kbd {
	background: #11180e;
	border: 1px solid #29362a;
	border-radius: 3px;
	padding: 1px 6px;
	font-family: "JetBrains Mono", monospace;
	font-size: 11px;
	color: #c2cfb6;
	margin: 0 1px;
}
#viewer-container {
	flex: 1;
	overflow: auto;
	display: flex;
	flex-direction: column;
	align-items: center;
	padding: 16px 0;
	gap: 8px;
	background: #0c130a;
}
#viewer-container .page-slot {
	background: #ffffff;
	box-shadow: 0 2px 12px rgba(0, 0, 0, 0.6);
	position: relative;
	flex-shrink: 0;
}
#viewer-container .page-slot canvas {
	display: block;
	position: relative;
	z-index: 1;
}
#viewer-container .page-slot .text-layer {
	position: absolute;
	left: 0;
	top: 0;
	right: 0;
	bottom: 0;
	overflow: hidden;
	line-height: 1;
	z-index: 2;
	user-select: text;
	forced-color-adjust: none;
	transform-origin: 0 0;
}
#viewer-container .page-slot .text-layer > span,
#viewer-container .page-slot .text-layer > br {
	color: transparent !important;
	position: absolute;
	white-space: pre;
	transform-origin: 0 0;
	cursor: text;
}
#viewer-container .page-slot .text-layer mark.find-hit {
	background: rgba(255, 220, 120, 0.50);
	color: transparent;
	padding: 0;
	margin: 0;
	border-radius: 1px;
}
#viewer-container .page-slot .text-layer mark.find-hit.current {
	background: rgba(212, 164, 100, 0.85);
}
#status {
	position: fixed;
	top: 50%;
	left: 50%;
	transform: translate(-50%, -50%);
	font-family: "Inria Sans", sans-serif;
	font-size: 15px;
	text-align: center;
}
@media (max-width: 640px) {
	#toolbar {
		flex-wrap: wrap;
		height: auto;
		padding: 6px 10px;
		gap: 4px;
	}
	#toolbar-nav { width: 100%; }
	#toolbar-controls { width: 100%; justify-content: flex-end; flex-wrap: wrap; }
	#toolbar-back, #toolbar-sep { display: none; }
	#zoom-level { display: none; }
	#fit-width, #fit-page, #help-toggle { display: none; }
	#download-text { display: none; }
}
`

function icon(name) {
	return `<i class="icon ph-duotone ph-${name}"></i>`
}

function buildNav(options) {
	let html = `<a href="/" id="toolbar-home">Applied Cryptography</a>`
	if (options.backLabel && options.backUrl) {
		html += `<span id="toolbar-sep">\u203A</span>`
		html += `<a href="${options.backUrl}" id="toolbar-back">${options.backLabel}</a>`
	}
	if (options.title) {
		html += `<span id="toolbar-badge">${options.title}</span>`
	}
	return html
}

const HELP_HTML = `
<h4>Navigation</h4>
<table>
<tr><td><kbd>←</kbd> <kbd>→</kbd></td><td>Previous / next page</td></tr>
<tr><td><kbd>PgUp</kbd> <kbd>PgDn</kbd></td><td>Previous / next page</td></tr>
<tr><td><kbd>Space</kbd> / <kbd>Shift</kbd>+<kbd>Space</kbd></td><td>Next / previous page</td></tr>
<tr><td><kbd>Home</kbd> <kbd>End</kbd></td><td>First / last page</td></tr>
<tr><td><kbd>G</kbd></td><td>Go to page\u2026</td></tr>
</table>
<h4>Zoom</h4>
<table>
<tr><td><kbd>+</kbd> <kbd>\u2212</kbd></td><td>Zoom in / out</td></tr>
<tr><td><kbd>0</kbd></td><td>Reset zoom (fit width)</td></tr>
<tr><td><kbd>W</kbd></td><td>Fit width</td></tr>
<tr><td><kbd>P</kbd></td><td>Fit page</td></tr>
</table>
<h4>View</h4>
<table>
<tr><td><kbd>M</kbd></td><td>Toggle single page / continuous</td></tr>
<tr><td><kbd>F</kbd></td><td>Toggle fullscreen</td></tr>
</table>
<h4>Find</h4>
<table>
<tr><td><kbd>Cmd/Ctrl</kbd>+<kbd>F</kbd> or <kbd>/</kbd></td><td>Open find</td></tr>
<tr><td><kbd>Enter</kbd> or <kbd>N</kbd></td><td>Next match</td></tr>
<tr><td><kbd>Shift</kbd>+<kbd>Enter</kbd> or <kbd>Shift</kbd>+<kbd>N</kbd></td><td>Previous match</td></tr>
<tr><td><kbd>Esc</kbd></td><td>Close find</td></tr>
</table>
<h4>Help</h4>
<table>
<tr><td><kbd>?</kbd></td><td>Show this help</td></tr>
<tr><td><kbd>Esc</kbd></td><td>Close help</td></tr>
</table>
`

export async function initViewer(pdfUrl, options = {}) {
	if (!document.querySelector(`link[data-pdfviewer-phosphor]`)) {
		const link = document.createElement(`link`)
		link.rel = `stylesheet`
		link.href = PHOSPHOR_HREF
		link.dataset.pdfviewerPhosphor = `1`
		document.head.appendChild(link)
	}

	const style = document.createElement(`style`)
	style.textContent = VIEWER_CSS
	document.head.appendChild(style)
	document.body.innerHTML = `<div id="status" style="color:#8b9881">Loading\u2026</div>`

	const pdf = await pdfjsLib.getDocument(pdfUrl).promise
	const numPages = pdf.numPages

	document.body.innerHTML = `
		<div id="toolbar">
			<div id="toolbar-nav">${buildNav(options)}</div>
			<div id="toolbar-controls">
				<span id="page-info">
					<span id="page-current" tabindex="0" title="Click to edit (G)">1</span>
					<span id="page-sep">/</span>
					<span id="page-total">${numPages}</span>
				</span>
				<button id="fit-width" class="tb-btn fit-btn" title="Fit width (W)" aria-label="Fit width">${icon(`arrows-out-line-horizontal`)}</button>
				<button id="fit-page" class="tb-btn fit-btn" title="Fit page (P)" aria-label="Fit page">${icon(`frame-corners`)}</button>
				<button id="zoom-out" class="tb-btn" title="Zoom out (\u2212)" aria-label="Zoom out">${icon(`magnifying-glass-minus`)}</button>
				<span id="zoom-level">100%</span>
				<button id="zoom-in" class="tb-btn" title="Zoom in (+)" aria-label="Zoom in">${icon(`magnifying-glass-plus`)}</button>
				<button id="mode-toggle" class="tb-btn" title="Toggle mode (M)" aria-label="Toggle view mode">${icon(`rows`)}</button>
				<button id="fullscreen-toggle" class="tb-btn" title="Fullscreen (F)" aria-label="Fullscreen">${icon(`corners-out`)}</button>
				<button id="find-toggle" class="tb-btn" title="Find (Cmd/Ctrl+F)" aria-label="Find">${icon(`magnifying-glass`)}</button>
				<button id="help-toggle" class="tb-btn" title="Keyboard shortcuts (?)" aria-label="Keyboard shortcuts">${icon(`keyboard`)}</button>
				<a id="download" href="${pdfUrl}" download title="Download PDF">${icon(`download-simple`)}<span id="download-text">Download</span></a>
			</div>
		</div>
		<div id="find-bar" hidden>
			<span class="find-icon">${icon(`magnifying-glass`)}</span>
			<input id="find-input" type="text" placeholder="Find in document" autocomplete="off" spellcheck="false" />
			<span id="find-counter">0 / 0</span>
			<button id="find-prev" class="tb-btn" title="Previous match (Shift+Enter)" aria-label="Previous match">${icon(`caret-up`)}</button>
			<button id="find-next" class="tb-btn" title="Next match (Enter)" aria-label="Next match">${icon(`caret-down`)}</button>
			<button id="find-close" class="tb-btn" title="Close (Esc)" aria-label="Close find">${icon(`x`)}</button>
		</div>
		<div id="viewer-container"></div>
		<div id="help-overlay" hidden>
			<div id="help-card">
				<div id="help-header">
					<span>Keyboard shortcuts</span>
					<button id="help-close" class="tb-btn" aria-label="Close">${icon(`x`)}</button>
				</div>
				<div id="help-content">${HELP_HTML}</div>
			</div>
		</div>
	`

	const container = document.getElementById(`viewer-container`)
	const findBar = document.getElementById(`find-bar`)
	const findInput = document.getElementById(`find-input`)
	const findCounter = document.getElementById(`find-counter`)
	const helpOverlay = document.getElementById(`help-overlay`)
	const fitWidthBtn = document.getElementById(`fit-width`)
	const fitPageBtn = document.getElementById(`fit-page`)
	const modeToggleBtn = document.getElementById(`mode-toggle`)
	const fullscreenBtn = document.getElementById(`fullscreen-toggle`)
	const zoomLevelEl = document.getElementById(`zoom-level`)
	const zoomInBtn = document.getElementById(`zoom-in`)
	const zoomOutBtn = document.getElementById(`zoom-out`)
	const findPrevBtn = document.getElementById(`find-prev`)
	const findNextBtn = document.getElementById(`find-next`)
	const findCloseBtn = document.getElementById(`find-close`)
	const findToggleBtn = document.getElementById(`find-toggle`)
	const helpToggleBtn = document.getElementById(`help-toggle`)
	const helpCloseBtn = document.getElementById(`help-close`)

	const fsAvailable = typeof document.documentElement.requestFullscreen === `function`
	if (!fsAvailable) fullscreenBtn.style.display = `none`

	const pixelRatio = Math.min(window.devicePixelRatio || 1, MAX_PIXEL_RATIO)

	const pageProxies = await Promise.all(
		Array.from({
			length: numPages
		}, (_, i) => pdf.getPage(i + 1))
	)
	const pageSizes = pageProxies.map((p) => {
		const vp = p.getViewport({
			scale: 1
		})
		return {
			width: vp.width,
			height: vp.height
		}
	})
	const intrinsicWidth = pageSizes[0].width
	const intrinsicHeight = pageSizes[0].height

	let singlePageMode = window.matchMedia(`(max-width: 640px)`).matches
	let currentPage = 1
	let fitMode = singlePageMode ? `page` : `width`

	function computeFitWidthScale() {
		return (container.clientWidth - 24) / intrinsicWidth
	}

	function computeFitPageScale() {
		return Math.min(
			(container.clientWidth - 24) / intrinsicWidth,
			(container.clientHeight - 24) / intrinsicHeight
		)
	}

	function recomputeScaleForFit() {
		if (fitMode === `width`) scale = computeFitWidthScale()
		else if (fitMode === `page`) scale = computeFitPageScale()
	}

	let baseScale = computeFitWidthScale()
	let scale = fitMode === `page` ? computeFitPageScale() : computeFitWidthScale()

	let slots = []
	let observer = null
	const renderTasks = new Map()
	const renderedPages = new Set()
	const textLayerData = new Map()
	let scaleStamp = 0
	let scrollFrac = 0
	let renderInProgress = 0

	const findState = {
		active: false,
		query: ``,
		matches: [],
		matchesByPage: new Map(),
		currentIdx: -1,
		textCache: new Map(),
		debounceTimer: null,
		pendingScrollToIdx: -1,
		searchToken: 0
	}

	function updateFitButtons() {
		fitWidthBtn.classList.toggle(`active`, fitMode === `width`)
		fitPageBtn.classList.toggle(`active`, fitMode === `page`)
	}

	function updateZoomLevel() {
		zoomLevelEl.textContent = `${Math.round((scale / baseScale) * 100)}%`
	}

	function updateModeIcon() {
		modeToggleBtn.innerHTML = singlePageMode ? icon(`rows`) : icon(`square`)
		modeToggleBtn.title = singlePageMode ?
			`Switch to continuous scroll (M)` :
			`Switch to single page (M)`
	}

	function isFullscreen() {
		return !!document.fullscreenElement
	}

	function updateFullscreenIcon() {
		if (!fsAvailable) return
		const fs = isFullscreen()
		fullscreenBtn.innerHTML = fs ? icon(`corners-in`) : icon(`corners-out`)
		fullscreenBtn.title = fs ? `Exit fullscreen (F)` : `Fullscreen (F)`
	}

	function captureScrollFrac() {
		if (renderInProgress === 0 && container.scrollHeight > container.clientHeight) {
			scrollFrac = container.scrollTop / (container.scrollHeight - container.clientHeight)
		}
	}

	function cancelRender(pageNum) {
		const task = renderTasks.get(pageNum)
		if (!task) return
		try {
			task.cancel()
		} catch {}
		renderTasks.delete(pageNum)
	}

	function releasePage(pageNum) {
		if (!renderedPages.has(pageNum)) return
		const slot = slots[pageNum - 1]
		if (slot) {
			const canvas = slot.querySelector(`canvas`)
			if (canvas) {
				canvas.width = 0
				canvas.height = 0
				canvas.remove()
			}
			const tl = slot.querySelector(`.text-layer`)
			if (tl) tl.remove()
		}
		textLayerData.delete(pageNum)
		const page = pageProxies[pageNum - 1]
		if (page && page.cleanup) {
			try {
				page.cleanup()
			} catch {}
		}
		renderedPages.delete(pageNum)
	}

	async function renderTextLayerForPage(pageNum, vp, slot, stamp) {
		const page = pageProxies[pageNum - 1]
		const textLayerDiv = document.createElement(`div`)
		textLayerDiv.className = `text-layer`
		textLayerDiv.style.width = `${Math.floor(vp.width)}px`
		textLayerDiv.style.height = `${Math.floor(vp.height)}px`
		slot.appendChild(textLayerDiv)

		try {
			const tl = new pdfjsLib.TextLayer({
				textContentSource: page.streamTextContent({
					includeMarkedContent: true,
					disableNormalization: false
				}),
				container: textLayerDiv,
				viewport: vp
			})
			await tl.render()
		} catch (e) {
			if (e?.name !== `AbortException` && e?.name !== `RenderingCancelledException`) {
				console.error(`Text layer error`, e)
			}
			textLayerDiv.remove()
			return null
		}

		if (stamp !== scaleStamp) {
			textLayerDiv.remove()
			return null
		}

		const spans = Array.from(textLayerDiv.querySelectorAll(`:scope > span`))
		return {
			spans
		}
	}

	async function renderPage(pageNum) {
		if (renderedPages.has(pageNum) || renderTasks.has(pageNum)) return
		const slot = slots[pageNum - 1]
		if (!slot) return
		const stamp = scaleStamp
		const page = pageProxies[pageNum - 1]
		const vp = page.getViewport({
			scale
		})

		if (stamp !== scaleStamp) return

		const canvas = document.createElement(`canvas`)
		canvas.width = Math.floor(vp.width * pixelRatio)
		canvas.height = Math.floor(vp.height * pixelRatio)
		canvas.style.width = `${Math.floor(vp.width)}px`
		canvas.style.height = `${Math.floor(vp.height)}px`
		const ctx = canvas.getContext(`2d`)
		ctx.scale(pixelRatio, pixelRatio)

		const task = page.render({
			canvasContext: ctx,
			viewport: vp
		})
		renderTasks.set(pageNum, task)
		try {
			await task.promise
			if (stamp !== scaleStamp) {
				canvas.width = 0
				canvas.height = 0
				return
			}
			slot.appendChild(canvas)
			renderedPages.add(pageNum)
		} catch (e) {
			if (e?.name !== `RenderingCancelledException`) {
				console.error(`PDF render error`, e)
			}
			return
		} finally {
			if (renderTasks.get(pageNum) === task) {
				renderTasks.delete(pageNum)
			}
		}

		const tlResult = await renderTextLayerForPage(pageNum, vp, slot, stamp)
		if (!tlResult) return
		textLayerData.set(pageNum, tlResult)
		if (findState.query) {
			applyHighlights(pageNum)
			if (findState.pendingScrollToIdx >= 0) {
				const m = findState.matches[findState.pendingScrollToIdx]
				if (m && m.pageNum === pageNum) {
					const mark = slot.querySelector(`mark.find-hit[data-match-idx="${findState.pendingScrollToIdx}"]`)
					if (mark) mark.scrollIntoView({
						block: `center`
					})
					findState.pendingScrollToIdx = -1
				}
			}
		}
	}

	function teardownObserver() {
		if (observer) {
			observer.disconnect();
			observer = null
		}
	}

	function setupObserver() {
		teardownObserver()
		if (singlePageMode) return
		observer = new IntersectionObserver((entries) => {
			for (const entry of entries) {
				const pageNum = +entry.target.dataset.page
				if (entry.isIntersecting) {
					renderPage(pageNum)
				} else {
					cancelRender(pageNum)
					releasePage(pageNum)
				}
			}
		}, {
			root: container,
			rootMargin: `${RENDER_MARGIN_PX}px 0px`
		})
		for (const slot of slots) observer.observe(slot)
	}

	function makeSlot(pageNum) {
		const size = pageSizes[pageNum - 1]
		const slot = document.createElement(`div`)
		slot.className = `page-slot`
		slot.dataset.page = String(pageNum)
		slot.style.width = `${Math.floor(size.width * scale)}px`
		slot.style.height = `${Math.floor(size.height * scale)}px`
		return slot
	}

	function buildSlots() {
		teardownObserver()
		for (const pageNum of Array.from(renderTasks.keys())) cancelRender(pageNum)
		for (const pageNum of Array.from(renderedPages)) releasePage(pageNum)
		container.innerHTML = ``
		slots = []
		scaleStamp++

		if (singlePageMode) {
			const slot = makeSlot(currentPage)
			container.appendChild(slot)
			slots[currentPage - 1] = slot
			renderPage(currentPage)
		} else {
			for (let i = 1; i <= numPages; i++) {
				const slot = makeSlot(i)
				container.appendChild(slot)
				slots.push(slot)
			}
		}
	}

	async function renderAllPages(resetScroll = false, scrollToPage = null) {
		if (resetScroll) scrollFrac = 0
		else captureScrollFrac()
		renderInProgress++
		try {
			buildSlots()
			if (!singlePageMode && scrollToPage && scrollToPage > 1) {
				scrollToPageCanvas(scrollToPage)
			} else if (container.scrollHeight > container.clientHeight) {
				container.scrollTop = scrollFrac * (container.scrollHeight - container.clientHeight)
			}
			if (!singlePageMode) setupObserver()
			updatePageInfo()
			updateZoomLevel()
		} finally {
			renderInProgress--
		}
	}

	function updatePageInfo() {
		if (!singlePageMode && slots.length) {
			const containerRect = container.getBoundingClientRect()
			let bestVisible = -1
			for (let i = 0; i < slots.length; i++) {
				const s = slots[i]
				if (!s) continue
				const rect = s.getBoundingClientRect()
				const visible = Math.max(0, Math.min(rect.bottom, containerRect.bottom) - Math.max(rect.top, containerRect.top))
				if (visible > bestVisible) {
					bestVisible = visible
					currentPage = i + 1
				}
				if (visible === 0 && bestVisible > 0) break
			}
		}
		const el = document.getElementById(`page-current`)
		if (el && el.tagName === `SPAN`) el.textContent = String(currentPage)
	}

	function navPage(delta) {
		const target = Math.max(1, Math.min(numPages, currentPage + delta))
		if (target === currentPage) return
		goToPage(target)
	}

	function goToPage(n) {
		n = Math.max(1, Math.min(numPages, n))
		if (n === currentPage && !singlePageMode) {
			const slot = slots[n - 1]
			if (slot) slot.scrollIntoView({
				block: `start`
			})
			return
		}
		currentPage = n
		if (singlePageMode) {
			renderAllPages(true).then(() => writeHash(true))
		} else {
			const slot = slots[n - 1]
			if (slot) slot.scrollIntoView({
				block: `start`
			})
			writeHash(true)
		}
	}

	function focusPageInput() {
		const el = document.getElementById(`page-current`)
		if (!el) return
		if (el.tagName === `INPUT`) {
			el.focus();
			el.select();
			return
		}
		const totalDigits = Math.max(2, String(numPages).length)
		const input = document.createElement(`input`)
		input.id = `page-current`
		input.type = `text`
		input.inputMode = `numeric`
		input.pattern = `[0-9]*`
		input.value = String(currentPage)
		input.style.width = `${totalDigits + 1}ch`
		el.replaceWith(input)
		input.focus()
		input.select()

		let committed = false

		function revert() {
			const span = document.createElement(`span`)
			span.id = `page-current`
			span.tabIndex = 0
			span.title = `Click to edit (G)`
			span.textContent = String(currentPage)
			span.addEventListener(`click`, focusPageInput)
			if (input.parentNode) input.replaceWith(span)
		}

		function commit() {
			if (committed) return
			committed = true
			const n = parseInt(input.value, 10)
			if (!isNaN(n) && n >= 1 && n <= numPages) goToPage(n)
			revert()
		}
		input.addEventListener(`keydown`, (e) => {
			if (e.key === `Enter`) {
				e.preventDefault()
				commit()
			} else if (e.key === `Escape`) {
				e.preventDefault()
				committed = true
				revert()
			}
		})
		input.addEventListener(`blur`, commit)
	}

	document.getElementById(`page-current`).addEventListener(`click`, focusPageInput)

	function parseHashPage() {
		for (const t of location.hash.slice(1).split(`&`)) {
			const m = t.match(/^page=(\d+)$/)
			if (!m) continue
			const n = parseInt(m[1], 10)
			return n >= 1 && n <= numPages ? n : null
		}
		return null
	}

	function writeHash(push) {
		const others = location.hash.slice(1).split(`&`).filter((t) => t && !/^page=\d+$/.test(t))
		const newHash = `#${[...others, `page=${currentPage}`].join(`&`)}`
		if (location.hash === newHash) return
		if (push) history.pushState(null, ``, newHash)
		else history.replaceState(null, ``, newHash)
	}

	function scrollToPageCanvas(page) {
		const s = slots[page - 1]
		if (s) s.scrollIntoView({
			block: `start`
		})
	}

	async function toggleMode() {
		if (!singlePageMode) updatePageInfo()
		const targetPage = currentPage
		singlePageMode = !singlePageMode
		updateModeIcon()
		baseScale = computeFitWidthScale()
		recomputeScaleForFit()
		await renderAllPages(true, singlePageMode ? null : targetPage)
		writeHash(false)
	}

	async function setFitMode(mode) {
		fitMode = mode
		recomputeScaleForFit()
		updateFitButtons()
		await renderAllPages()
	}

	async function zoomBy(delta) {
		const newScale = scale + delta
		if (newScale < baseScale * 0.5 || newScale > baseScale * 3) return
		scale = newScale
		fitMode = `custom`
		updateFitButtons()
		await renderAllPages()
	}

	function toggleFullscreen() {
		if (!fsAvailable) return
		if (isFullscreen()) document.exitFullscreen()
		else document.documentElement.requestFullscreen()
	}

	document.addEventListener(`fullscreenchange`, updateFullscreenIcon)

	function openHelp() {
		helpOverlay.hidden = false
		helpOverlay.dataset.open = `1`
	}

	function closeHelp() {
		helpOverlay.hidden = true
		delete helpOverlay.dataset.open
	}
	helpToggleBtn.addEventListener(`click`, openHelp)
	helpCloseBtn.addEventListener(`click`, closeHelp)
	helpOverlay.addEventListener(`click`, (e) => {
		if (e.target === helpOverlay) closeHelp()
	})

	async function ensureTextContent(pageNum) {
		let entry = findState.textCache.get(pageNum)
		if (entry) return entry
		const tc = await pageProxies[pageNum - 1].getTextContent()
		const items = []
		for (const item of tc.items) {
			if (typeof item.str === `string`) items.push(item.str.toLowerCase())
		}
		entry = {
			items
		}
		findState.textCache.set(pageNum, entry)
		return entry
	}

	function updateFindCounter() {
		if (!findState.query) {
			findCounter.textContent = `0 / 0`
		} else if (findState.matches.length === 0) {
			findCounter.textContent = `No matches`
		} else {
			findCounter.textContent = `${findState.currentIdx + 1} / ${findState.matches.length}`
		}
	}

	function clearAllHighlights() {
		for (const pageNum of Array.from(textLayerData.keys())) {
			applyHighlights(pageNum)
		}
	}

	function applyHighlights(pageNum) {
		const tld = textLayerData.get(pageNum)
		if (!tld) return
		const {
			spans
		} = tld
		for (const span of spans) {
			if (span.dataset.originalText !== undefined) {
				span.textContent = span.dataset.originalText
				delete span.dataset.originalText
			}
		}
		const q = findState.query
		if (!q) return

		const pageMap = findState.matchesByPage.get(pageNum)
		if (!pageMap) return

		let localIdx = 0
		for (const span of spans) {
			const text = span.textContent
			const lower = text.toLowerCase()
			let pos = 0
			const occurrences = []
			while (true) {
				const idx = lower.indexOf(q, pos)
				if (idx === -1) break
				occurrences.push({
					start: idx,
					end: idx + q.length,
					localIdx: localIdx++
				})
				pos = idx + q.length
			}
			if (occurrences.length === 0) continue

			span.dataset.originalText = text
			span.innerHTML = ``
			let cur = 0
			for (const o of occurrences) {
				if (o.start > cur) span.appendChild(document.createTextNode(text.slice(cur, o.start)))
				const mark = document.createElement(`mark`)
				mark.className = `find-hit`
				const gIdx = pageMap.get(o.localIdx)
				if (gIdx !== undefined) {
					mark.dataset.matchIdx = String(gIdx)
					if (gIdx === findState.currentIdx) mark.classList.add(`current`)
				}
				mark.textContent = text.slice(o.start, o.end)
				span.appendChild(mark)
				cur = o.end
			}
			if (cur < text.length) span.appendChild(document.createTextNode(text.slice(cur)))
		}
	}

	function updateCurrentMark() {
		container.querySelectorAll(`mark.find-hit.current`).forEach((m) => m.classList.remove(`current`))
		container.querySelectorAll(`mark.find-hit[data-match-idx="${findState.currentIdx}"]`).forEach((m) => m.classList.add(`current`))
	}

	function goToMatch(globalIdx) {
		if (findState.matches.length === 0) return
		const N = findState.matches.length
		findState.currentIdx = ((globalIdx % N) + N) % N
		updateFindCounter()

		const m = findState.matches[findState.currentIdx]
		findState.pendingScrollToIdx = findState.currentIdx

		if (singlePageMode && m.pageNum !== currentPage) {
			currentPage = m.pageNum
			renderAllPages(true).then(() => {
				writeHash(true)
			})
			return
		}

		const slot = slots[m.pageNum - 1]
		if (slot) slot.scrollIntoView({
			block: `center`
		})

		if (textLayerData.has(m.pageNum)) {
			updateCurrentMark()
			const mark = slot?.querySelector(`mark.find-hit[data-match-idx="${findState.currentIdx}"]`)
			if (mark) {
				mark.scrollIntoView({
					block: `center`
				})
				findState.pendingScrollToIdx = -1
			}
		}
	}

	async function runSearch(query) {
		const q = query.toLowerCase()
		const token = ++findState.searchToken
		findState.query = q
		findState.matches = []
		findState.matchesByPage = new Map()
		findState.currentIdx = -1

		if (!q) {
			clearAllHighlights()
			updateFindCounter()
			return
		}

		findCounter.textContent = `Searching\u2026`

		for (let pageNum = 1; pageNum <= numPages; pageNum++) {
			const entry = await ensureTextContent(pageNum)
			if (token !== findState.searchToken) return
			let localIdx = 0
			let pageMap = null
			for (const item of entry.items) {
				let pos = 0
				while (true) {
					const idx = item.indexOf(q, pos)
					if (idx === -1) break
					const globalIdx = findState.matches.length
					findState.matches.push({
						pageNum,
						localIdx,
						globalIdx
					})
					if (!pageMap) {
						pageMap = new Map()
						findState.matchesByPage.set(pageNum, pageMap)
					}
					pageMap.set(localIdx, globalIdx)
					pos = idx + q.length
					localIdx++
				}
			}
		}

		findState.currentIdx = findState.matches.length > 0 ? 0 : -1
		updateFindCounter()
		for (const pageNum of textLayerData.keys()) applyHighlights(pageNum)
		if (findState.currentIdx >= 0) goToMatch(0)
	}

	function scheduleSearch(query) {
		if (findState.debounceTimer) clearTimeout(findState.debounceTimer)
		findState.debounceTimer = setTimeout(() => runSearch(query), FIND_DEBOUNCE_MS)
	}

	function openFindBar() {
		findBar.hidden = false
		findState.active = true
		findInput.focus()
		findInput.select()
	}

	function closeFindBar() {
		findBar.hidden = true
		findInput.value = ``
		findState.active = false
		findState.query = ``
		findState.matches = []
		findState.matchesByPage = new Map()
		findState.currentIdx = -1
		findState.searchToken++
		clearAllHighlights()
		updateFindCounter()
	}

	findInput.addEventListener(`input`, () => scheduleSearch(findInput.value))
	findInput.addEventListener(`keydown`, (e) => {
		if (e.key === `Enter`) {
			e.preventDefault()
			if (findState.matches.length > 0) {
				goToMatch(findState.currentIdx + (e.shiftKey ? -1 : 1))
			}
		} else if (e.key === `Escape`) {
			e.preventDefault()
			closeFindBar()
		}
	})
	findPrevBtn.addEventListener(`click`, () => {
		if (findState.matches.length > 0) goToMatch(findState.currentIdx - 1)
	})
	findNextBtn.addEventListener(`click`, () => {
		if (findState.matches.length > 0) goToMatch(findState.currentIdx + 1)
	})
	findCloseBtn.addEventListener(`click`, closeFindBar)
	findToggleBtn.addEventListener(`click`, () => {
		if (findState.active) closeFindBar()
		else openFindBar()
	})

	updateFitButtons()
	updateModeIcon()
	updateFullscreenIcon()

	const initialPage = parseHashPage()
	if (initialPage) currentPage = initialPage

	await renderAllPages(false, initialPage)

	let hashUpdateTimer
	container.addEventListener(`scroll`, () => {
		captureScrollFrac()
		if (!singlePageMode) {
			updatePageInfo()
			clearTimeout(hashUpdateTimer)
			hashUpdateTimer = setTimeout(() => writeHash(false), 300)
		}
	})

	modeToggleBtn.addEventListener(`click`, toggleMode)
	fullscreenBtn.addEventListener(`click`, toggleFullscreen)
	fitWidthBtn.addEventListener(`click`, () => setFitMode(`width`))
	fitPageBtn.addEventListener(`click`, () => setFitMode(`page`))
	zoomInBtn.addEventListener(`click`, () => zoomBy(+SCALE_STEP))
	zoomOutBtn.addEventListener(`click`, () => zoomBy(-SCALE_STEP))

	let wheelNavLock = 0
	container.addEventListener(`wheel`, (e) => {
		if (!singlePageMode) return
		const now = Date.now()
		if (now - wheelNavLock < 400) return
		const atTop = container.scrollTop <= 0
		const atBottom = container.scrollTop + container.clientHeight >= container.scrollHeight - 1
		if (e.deltaY > 0 && atBottom && currentPage < numPages) {
			e.preventDefault()
			wheelNavLock = now
			currentPage++
			renderAllPages(true).then(() => writeHash(true))
		} else if (e.deltaY < 0 && atTop && currentPage > 1) {
			e.preventDefault()
			wheelNavLock = now
			currentPage--
			renderAllPages(true).then(() => {
				if (container.scrollHeight > container.clientHeight) {
					container.scrollTop = container.scrollHeight - container.clientHeight
				}
				writeHash(true)
			})
		}
	}, {
		passive: false
	})

	window.addEventListener(`hashchange`, () => {
		const p = parseHashPage()
		if (!p || p === currentPage) return
		currentPage = p
		if (singlePageMode) renderAllPages(true)
		else scrollToPageCanvas(p)
	})

	let resizeTimer
	window.addEventListener(`resize`, () => {
		clearTimeout(resizeTimer)
		resizeTimer = setTimeout(() => {
			baseScale = computeFitWidthScale()
			recomputeScaleForFit()
			renderAllPages()
		}, 200)
	})

	document.addEventListener(`keydown`, (e) => {
		if (helpOverlay.dataset.open === `1`) {
			if (e.key === `Escape`) {
				e.preventDefault()
				closeHelp()
			}
			return
		}

		const tgt = e.target
		const isEditable = tgt && (tgt.tagName === `INPUT` || tgt.tagName === `TEXTAREA` || tgt.isContentEditable)
		if (isEditable) return

		const cmd = e.metaKey || e.ctrlKey
		const alt = e.altKey

		if (cmd && (e.key === `f` || e.key === `F`)) {
			e.preventDefault()
			openFindBar()
			return
		}
		if (cmd || alt) return

		switch (e.key) {
			case `ArrowLeft`:
			case `PageUp`:
				e.preventDefault()
				navPage(-1)
				break
			case `ArrowRight`:
			case `PageDown`:
				e.preventDefault()
				navPage(+1)
				break
			case ` `:
				e.preventDefault()
				navPage(e.shiftKey ? -1 : +1)
				break
			case `Home`:
				e.preventDefault()
				goToPage(1)
				break
			case `End`:
				e.preventDefault()
				goToPage(numPages)
				break
			case `g`:
			case `G`:
				e.preventDefault()
				focusPageInput()
				break
			case `+`:
			case `=`:
				e.preventDefault()
				zoomBy(+SCALE_STEP)
				break
			case `-`:
				e.preventDefault()
				zoomBy(-SCALE_STEP)
				break
			case `0`:
				e.preventDefault()
				setFitMode(`width`)
				break
			case `w`:
			case `W`:
				e.preventDefault()
				setFitMode(`width`)
				break
			case `p`:
			case `P`:
				e.preventDefault()
				setFitMode(`page`)
				break
			case `m`:
			case `M`:
				e.preventDefault()
				toggleMode()
				break
			case `f`:
			case `F`:
				e.preventDefault()
				toggleFullscreen()
				break
			case `/`:
				e.preventDefault()
				openFindBar()
				break
			case `?`:
				e.preventDefault()
				openHelp()
				break
			case `n`:
			case `N`:
				if (findState.active && findState.matches.length > 0) {
					e.preventDefault()
					goToMatch(findState.currentIdx + (e.shiftKey ? -1 : 1))
				}
				break
			case `Escape`:
				if (findState.active) {
					e.preventDefault()
					closeFindBar()
				}
				break
		}
	})
}
