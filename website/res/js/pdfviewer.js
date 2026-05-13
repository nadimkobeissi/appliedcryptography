import * as pdfjsLib from "https://cdn.jsdelivr.net/npm/pdfjs-dist@5.7.284/+esm"

pdfjsLib.GlobalWorkerOptions.workerSrc = `https://cdn.jsdelivr.net/npm/pdfjs-dist@5.7.284/build/pdf.worker.min.mjs`

const SCALE_STEP = 0.25

const VIEWER_CSS = `
#toolbar {
	display: flex;
	align-items: center;
	justify-content: space-between;
	padding: 0 16px;
	height: 46px;
	background: #0f1a0a;
	font-family: "Inria Sans", sans-serif;
	color: #c8d9b7;
	flex-shrink: 0;
	border-bottom: 2px solid #2c5e1a;
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
	color: #78d159;
	text-decoration: none;
	font-weight: 700;
	font-size: 14px;
	white-space: nowrap;
	transition: color 0.2s ease;
}
#toolbar-nav a:hover {
	color: #b8e19f;
}
#toolbar-sep {
	color: #3a5a2a;
	font-size: 13px;
	flex-shrink: 0;
}
#toolbar-badge {
	font-family: "JetBrains Mono", monospace;
	font-size: 0.75rem;
	color: #8cb369;
	background: #1a2c0d;
	padding: 3px 10px;
	border-radius: 50px;
	white-space: nowrap;
	border: 1px solid #2c5e1a;
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
	color: #a8c29b;
	min-width: 54px;
	text-align: center;
}
#toolbar-controls button {
	background: none;
	color: #c8d9b7;
	border: 1px solid #2c5e1a;
	border-radius: 4px;
	width: 28px;
	height: 28px;
	font-size: 16px;
	cursor: pointer;
	display: flex;
	align-items: center;
	justify-content: center;
	padding: 0;
	line-height: 1;
	transition: all 0.2s ease;
}
#toolbar-controls button:hover {
	background: #1e3e12;
	color: #78d159;
	border-color: #4a9c31;
}
#zoom-level {
	font-family: "JetBrains Mono", monospace;
	font-size: 0.7rem;
	min-width: 36px;
	text-align: center;
	color: #a8c29b;
}
#download {
	color: #0f1a0a;
	text-decoration: none;
	font-family: "Inria Sans", sans-serif;
	font-size: 0.8rem;
	font-weight: 700;
	padding: 4px 12px;
	background: #4a9c31;
	border-radius: 8px;
	white-space: nowrap;
	transition: all 0.2s ease;
}
#download:hover {
	background: #78d159;
}
#viewer-container {
	flex: 1;
	overflow: auto;
	display: flex;
	flex-direction: column;
	align-items: center;
	padding: 16px 0;
	gap: 8px;
	background: #1a1a1a;
}
#viewer-container canvas {
	display: block;
	box-shadow: 0 2px 12px rgba(0, 0, 0, 0.6);
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
	#toolbar-nav {
		width: 100%;
	}
	#toolbar-controls {
		width: 100%;
		justify-content: flex-end;
	}
	#toolbar-back,
	#toolbar-sep {
		display: none;
	}
	#zoom-level {
		display: none;
	}
}
`

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

export async function initViewer(pdfUrl, options = {}) {
	const style = document.createElement(`style`)
	style.textContent = VIEWER_CSS
	document.head.appendChild(style)
	document.body.innerHTML = `<div id="status" style="color:#6a8a5a">Loading\u2026</div>`

	const pdf = await pdfjsLib.getDocument(pdfUrl).promise

	const numPages = pdf.numPages
	document.body.innerHTML = `
		<div id="toolbar">
			<div id="toolbar-nav">
				${buildNav(options)}
			</div>
			<div id="toolbar-controls">
				<span id="page-info">1 / ${numPages}</span>
				<button id="mode-toggle" title="Switch to continuous scroll">\u25ad</button>
				<button id="zoom-out" title="Zoom out">\u2212</button>
				<span id="zoom-level">100%</span>
				<button id="zoom-in" title="Zoom in">+</button>
				<a id="download" href="${pdfUrl}" download title="Download PDF">Download</a>
			</div>
		</div>
		<div id="viewer-container"></div>
	`

	const container = document.getElementById(`viewer-container`)
	const pixelRatio = window.devicePixelRatio || 1
	const firstPage = await pdf.getPage(1)
	const intrinsicVp = firstPage.getViewport({ scale: 1 })
	const intrinsicWidth = intrinsicVp.width
	const intrinsicHeight = intrinsicVp.height

	let singlePageMode = true
	let currentPage = 1

	function computeBaseScale() {
		const w = (container.clientWidth - 24) / intrinsicWidth
		if (!singlePageMode) return w
		const h = (container.clientHeight - 24) / intrinsicHeight
		return Math.min(w, h)
	}

	let baseScale = computeBaseScale()
	let scale = baseScale

	let renderToken = 0
	let renderInProgress = 0
	let scrollFrac = 0

	function captureScrollFrac() {
		if (renderInProgress === 0 && container.scrollHeight > container.clientHeight) {
			scrollFrac = container.scrollTop / (container.scrollHeight - container.clientHeight)
		}
	}

	async function renderAllPages(resetScroll = false) {
		const myToken = ++renderToken
		if (resetScroll) {
			scrollFrac = 0
		} else {
			captureScrollFrac()
		}
		renderInProgress++
		try {
			container.innerHTML = ``
			const start = singlePageMode ? currentPage : 1
			const end = singlePageMode ? currentPage : numPages
			for (let i = start; i <= end; i++) {
				const page = await pdf.getPage(i)
				if (myToken !== renderToken) return
				const vp = page.getViewport({
					scale
				})
				const canvas = document.createElement(`canvas`)
				canvas.width = Math.floor(vp.width * pixelRatio)
				canvas.height = Math.floor(vp.height * pixelRatio)
				canvas.style.width = `${Math.floor(vp.width)}px`
				canvas.style.height = `${Math.floor(vp.height)}px`
				canvas.dataset.page = i
				container.appendChild(canvas)
				const ctx = canvas.getContext(`2d`)
				ctx.scale(pixelRatio, pixelRatio)
				await page.render({
					canvasContext: ctx,
					viewport: vp
				}).promise
				if (myToken !== renderToken) return
			}
			if (myToken !== renderToken) return
			if (container.scrollHeight > container.clientHeight) {
				container.scrollTop = scrollFrac * (container.scrollHeight - container.clientHeight)
			}
			updatePageInfo()
			document.getElementById(`zoom-level`).textContent =
				`${Math.round((scale / baseScale) * 100)}%`
		} finally {
			renderInProgress--
		}
	}

	function updatePageInfo() {
		if (!singlePageMode) {
			const canvases = container.querySelectorAll(`canvas`)
			if (canvases.length) {
				const containerRect = container.getBoundingClientRect()
				let bestVisible = -1
				canvases.forEach((c) => {
					const rect = c.getBoundingClientRect()
					const visible = Math.max(0, Math.min(rect.bottom, containerRect.bottom) - Math.max(rect.top, containerRect.top))
					if (visible > bestVisible) {
						bestVisible = visible
						currentPage = +c.dataset.page
					}
				})
			}
		}
		document.getElementById(`page-info`).textContent = `${currentPage} / ${numPages}`
	}

	await renderAllPages()

	container.addEventListener(`scroll`, () => {
		captureScrollFrac()
		if (!singlePageMode) updatePageInfo()
	})

	const modeToggle = document.getElementById(`mode-toggle`)
	modeToggle.addEventListener(`click`, async () => {
		if (!singlePageMode) {
			updatePageInfo()
		}
		singlePageMode = !singlePageMode
		modeToggle.textContent = singlePageMode ? `▭` : `☰`
		modeToggle.title = singlePageMode ? `Switch to continuous scroll` : `Switch to single page mode`
		baseScale = computeBaseScale()
		scale = baseScale
		await renderAllPages(true)
	})

	document.addEventListener(`keydown`, async (e) => {
		if (!singlePageMode) return
		if (e.key === `ArrowLeft` && currentPage > 1) {
			e.preventDefault()
			currentPage--
			await renderAllPages(true)
		} else if (e.key === `ArrowRight` && currentPage < numPages) {
			e.preventDefault()
			currentPage++
			await renderAllPages(true)
		}
	})

	document.getElementById(`zoom-in`).addEventListener(`click`, async () => {
		if (scale >= baseScale * 3) return
		scale += SCALE_STEP
		await renderAllPages()
	})

	document.getElementById(`zoom-out`).addEventListener(`click`, async () => {
		if (scale <= baseScale * 0.5) return
		scale -= SCALE_STEP
		await renderAllPages()
	})

	let resizeTimer
	window.addEventListener(`resize`, () => {
		clearTimeout(resizeTimer)
		resizeTimer = setTimeout(() => {
			const ratio = scale / baseScale
			baseScale = computeBaseScale()
			scale = baseScale * ratio
			renderAllPages()
		}, 200)
	})
}