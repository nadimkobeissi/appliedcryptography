import * as pdfjsLib from "https://cdn.jsdelivr.net/npm/pdfjs-dist@5.7.284/+esm"

pdfjsLib.GlobalWorkerOptions.workerSrc = `https://cdn.jsdelivr.net/npm/pdfjs-dist@5.7.284/build/pdf.worker.min.mjs`

const SCALE_STEP = 0.25
const MAX_PIXEL_RATIO = 2
const RENDER_MARGIN_PX = 800

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
#viewer-container .page-slot {
	background: #ffffff;
	box-shadow: 0 2px 12px rgba(0, 0, 0, 0.6);
	position: relative;
	flex-shrink: 0;
}
#viewer-container .page-slot canvas {
	display: block;
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
		html += `<span id="toolbar-sep">\u203a</span>`
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
	const pixelRatio = Math.min(window.devicePixelRatio || 1, MAX_PIXEL_RATIO)

	// Pre-fetch all page proxies so placeholder slots can have accurate
	// per-page dimensions immediately (stable scrollHeight before any render).
	// PDFPageProxy is lightweight — content streams aren't parsed until render().
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

	function computeBaseScale() {
		const w = (container.clientWidth - 24) / intrinsicWidth
		if (!singlePageMode) return w
		const h = (container.clientHeight - 24) / intrinsicHeight
		return Math.min(w, h)
	}

	let baseScale = computeBaseScale()
	let scale = baseScale

	let slots = []
	let observer = null
	const renderTasks = new Map()
	const renderedPages = new Set()
	let scaleStamp = 0
	let scrollFrac = 0
	let renderInProgress = 0

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
				// Setting dimensions to 0 forces the browser to release the
				// canvas backing store immediately rather than waiting for GC.
				canvas.width = 0
				canvas.height = 0
				canvas.remove()
			}
		}
		const page = pageProxies[pageNum - 1]
		if (page && page.cleanup) {
			try {
				page.cleanup()
			} catch {}
		}
		renderedPages.delete(pageNum)
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
		} finally {
			if (renderTasks.get(pageNum) === task) {
				renderTasks.delete(pageNum)
			}
		}
	}

	function teardownObserver() {
		if (observer) {
			observer.disconnect()
			observer = null
		}
	}

	function setupObserver() {
		teardownObserver()
		if (singlePageMode) return
		observer = new IntersectionObserver(
			(entries) => {
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
			}
		)
		for (const slot of slots) {
			observer.observe(slot)
		}
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
		// Cancel in-flight renders and free all canvases before tearing down.
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
			setupObserver()
		}
	}

	async function renderAllPages(resetScroll = false) {
		if (resetScroll) {
			scrollFrac = 0
		} else {
			captureScrollFrac()
		}
		renderInProgress++
		try {
			buildSlots()
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
			const visibleSlots = container.querySelectorAll(`.page-slot`)
			if (visibleSlots.length) {
				const containerRect = container.getBoundingClientRect()
				let bestVisible = -1
				visibleSlots.forEach((s) => {
					const rect = s.getBoundingClientRect()
					const visible = Math.max(0, Math.min(rect.bottom, containerRect.bottom) - Math.max(rect.top, containerRect.top))
					if (visible > bestVisible) {
						bestVisible = visible
						currentPage = +s.dataset.page
					}
				})
			}
		}
		document.getElementById(`page-info`).textContent = `${currentPage} / ${numPages}`
	}

	function parseHashPage() {
		const m = location.hash.match(/page=(\d+)/)
		if (!m) return null
		const n = parseInt(m[1], 10)
		return n >= 1 && n <= numPages ? n : null
	}

	function writeHash(push) {
		const newHash = `#page=${currentPage}`
		if (location.hash === newHash) return
		if (push) {
			history.pushState(null, ``, newHash)
		} else {
			history.replaceState(null, ``, newHash)
		}
	}

	async function scrollToPageCanvas(page) {
		const s = container.querySelector(`.page-slot[data-page="${page}"]`)
		if (s) s.scrollIntoView({
			block: `start`
		})
	}

	const initialPage = parseHashPage()
	if (initialPage) currentPage = initialPage

	await renderAllPages()

	if (!singlePageMode && initialPage) {
		await scrollToPageCanvas(initialPage)
	}

	let hashUpdateTimer
	container.addEventListener(`scroll`, () => {
		captureScrollFrac()
		if (!singlePageMode) {
			updatePageInfo()
			clearTimeout(hashUpdateTimer)
			hashUpdateTimer = setTimeout(() => writeHash(false), 300)
		}
	})

	const modeToggle = document.getElementById(`mode-toggle`)
	modeToggle.textContent = singlePageMode ? `▭` : `☰`
	modeToggle.title = singlePageMode ? `Switch to continuous scroll` : `Switch to single page mode`
	modeToggle.addEventListener(`click`, async () => {
		if (!singlePageMode) {
			updatePageInfo()
		}
		const targetPage = currentPage
		singlePageMode = !singlePageMode
		modeToggle.textContent = singlePageMode ? `▭` : `☰`
		modeToggle.title = singlePageMode ? `Switch to continuous scroll` : `Switch to single page mode`
		baseScale = computeBaseScale()
		scale = baseScale
		await renderAllPages(true)
		if (!singlePageMode) {
			await scrollToPageCanvas(targetPage)
		}
		writeHash(false)
	})

	document.addEventListener(`keydown`, async (e) => {
		if (!singlePageMode) return
		if (((e.key === `ArrowLeft`) || (e.key === `ArrowUp`)) && currentPage > 1) {
			e.preventDefault()
			currentPage--
			await renderAllPages(true)
			writeHash(true)
		} else if (((e.key === `ArrowRight`) || (e.key === `ArrowDown`)) && currentPage < numPages) {
			e.preventDefault()
			currentPage++
			await renderAllPages(true)
			writeHash(true)
		}
	})

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

	window.addEventListener(`hashchange`, async () => {
		const p = parseHashPage()
		if (!p || p === currentPage) return
		currentPage = p
		if (singlePageMode) {
			await renderAllPages(true)
		} else {
			await scrollToPageCanvas(p)
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