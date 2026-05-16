const page = document.body.dataset.page;

document.querySelectorAll("[data-nav]").forEach((link) => {
  if (link.dataset.nav === page) {
    link.setAttribute("aria-current", "page");
  }
});

const toggle = document.querySelector(".nav-toggle");
const nav = document.querySelector(".site-nav");
if (toggle && nav) {
  toggle.addEventListener("click", () => {
    const open = nav.classList.toggle("open");
    toggle.setAttribute("aria-expanded", String(open));
  });
}

document.querySelectorAll(".mesh-canvas").forEach((canvas, canvasIndex) => {
  const ctx = canvas.getContext("2d");
  const nodes = Array.from({ length: canvas.dataset.scene === "hero" ? 18 : 12 }, (_, index) => ({
    x: 0,
    y: 0,
    tier: index % 4,
    phase: index * 0.61 + canvasIndex
  }));

  function resize() {
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.floor(canvas.clientWidth * dpr));
    canvas.height = Math.max(1, Math.floor(canvas.clientHeight * dpr));
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function draw(time) {
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    const heroScene = canvas.dataset.scene === "hero";
    const cx = w * (heroScene ? 0.62 : 0.70);
    const cy = h * (heroScene ? 0.40 : 0.48);
    const rx = Math.max(160, w * 0.31);
    const ry = Math.max(110, h * (heroScene ? 0.22 : 0.25));
    ctx.clearRect(0, 0, w, h);

    ctx.lineWidth = 1;
    ctx.strokeStyle = "rgba(120, 215, 255, .12)";
    for (let x = 0; x < w; x += 72) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }
    for (let y = 0; y < h; y += 72) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    nodes.forEach((node, index) => {
      const angle = (index / nodes.length) * Math.PI * 2 + Math.sin(time / 2600 + node.phase) * 0.08;
      node.x = cx + Math.cos(angle) * rx + Math.sin(time / 1600 + index) * 10;
      node.y = cy + Math.sin(angle) * ry + Math.cos(time / 1900 + index) * 8;
    });

    nodes.forEach((node, index) => {
      const next = nodes[(index + 5) % nodes.length];
      const other = nodes[(index + 9) % nodes.length];
      drawLink(node, next, "rgba(105, 229, 181, .22)");
      drawLink(node, other, "rgba(255, 211, 110, .12)");
    });

    nodes.forEach((node, index) => {
      const colors = ["#69e5b5", "#78d7ff", "#ffd36e", "#ff7f70"];
      ctx.fillStyle = colors[node.tier];
      ctx.beginPath();
      ctx.rect(node.x - 8, node.y - 8, 16, 16);
      ctx.fill();
      ctx.strokeStyle = "rgba(246,244,234,.45)";
      ctx.strokeRect(node.x - 11, node.y - 11, 22, 22);
      if (heroScene && index < 10 && w > 760 && node.x > w * 0.50) {
        ctx.fillStyle = "rgba(246,244,234,.72)";
        ctx.font = "12px ui-monospace, monospace";
        ctx.fillText(`disk-${String(index).padStart(4, "0")}`, node.x + 16, node.y + 4);
      }
    });

    requestAnimationFrame(draw);
  }

  function drawLink(a, b, color) {
    ctx.strokeStyle = color;
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  }

  resize();
  window.addEventListener("resize", resize);
  requestAnimationFrame(draw);
});
