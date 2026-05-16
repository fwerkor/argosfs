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

const palette = {
  line: "rgba(148, 163, 184, .18)",
  faint: "rgba(148, 163, 184, .08)",
  green: "rgba(125, 211, 167, .82)",
  cyan: "rgba(103, 232, 249, .80)",
  amber: "rgba(251, 191, 36, .82)",
  violet: "rgba(196, 181, 253, .78)",
  panel: "rgba(15, 23, 42, .58)",
  text: "rgba(247, 249, 251, .72)"
};

function drawRoundedRect(ctx, x, y, width, height, radius) {
  const r = Math.min(radius, width / 2, height / 2);
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + width, y, x + width, y + height, r);
  ctx.arcTo(x + width, y + height, x, y + height, r);
  ctx.arcTo(x, y + height, x, y, r);
  ctx.arcTo(x, y, x + width, y, r);
  ctx.closePath();
}

function drawCanvas(canvas) {
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(1, canvas.clientWidth);
  const h = Math.max(1, canvas.clientHeight);
  canvas.width = Math.floor(w * dpr);
  canvas.height = Math.floor(h * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  ctx.lineWidth = 1;
  ctx.strokeStyle = palette.faint;
  const grid = w > 900 ? 96 : 72;
  for (let x = 0; x <= w; x += grid) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, h);
    ctx.stroke();
  }
  for (let y = 0; y <= h; y += grid) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  const heroScene = canvas.dataset.scene === "hero";
  const originX = heroScene ? w * 0.60 : w * 0.58;
  const originY = heroScene ? h * 0.38 : h * 0.42;
  const scale = Math.min(Math.max(w / 1200, 0.72), 1.12);
  const boxW = 122 * scale;
  const boxH = 46 * scale;
  const gapX = 158 * scale;
  const gapY = 86 * scale;

  const nodes = [
    { id: "POSIX", x: originX - gapX * 1.35, y: originY - gapY * .85, color: palette.cyan },
    { id: "Stripe", x: originX - gapX * .32, y: originY - gapY * .85, color: palette.green },
    { id: "Parity", x: originX + gapX * .72, y: originY - gapY * .85, color: palette.amber },
    { id: "Hot tier", x: originX - gapX * .85, y: originY + gapY * .10, color: palette.green },
    { id: "Cold tier", x: originX + gapX * .18, y: originY + gapY * .10, color: palette.violet },
    { id: "Metadata", x: originX - gapX * .32, y: originY + gapY * 1.05, color: palette.cyan },
    { id: "Autopilot", x: originX + gapX * .72, y: originY + gapY * 1.05, color: palette.amber }
  ];

  const visibleNodes = nodes.filter((node) => (
    node.x > -boxW && node.x < w + boxW && node.y > -boxH && node.y < h + boxH
  ));

  const links = [
    ["POSIX", "Stripe"],
    ["Stripe", "Parity"],
    ["Stripe", "Hot tier"],
    ["Stripe", "Cold tier"],
    ["Hot tier", "Metadata"],
    ["Cold tier", "Metadata"],
    ["Metadata", "Autopilot"],
    ["Autopilot", "Hot tier"],
    ["Autopilot", "Cold tier"]
  ];

  ctx.lineWidth = 1.4;
  links.forEach(([from, to]) => {
    const a = visibleNodes.find((node) => node.id === from);
    const b = visibleNodes.find((node) => node.id === to);
    if (!a || !b) return;
    ctx.strokeStyle = palette.line;
    ctx.beginPath();
    ctx.moveTo(a.x + boxW / 2, a.y + boxH / 2);
    ctx.lineTo(b.x + boxW / 2, b.y + boxH / 2);
    ctx.stroke();
  });

  visibleNodes.forEach((node) => {
    drawRoundedRect(ctx, node.x, node.y, boxW, boxH, 14 * scale);
    ctx.fillStyle = palette.panel;
    ctx.fill();
    ctx.strokeStyle = node.color;
    ctx.stroke();

    ctx.fillStyle = node.color;
    ctx.beginPath();
    ctx.arc(node.x + 18 * scale, node.y + boxH / 2, 4.5 * scale, 0, Math.PI * 2);
    ctx.fill();

    if (w > 620) {
      ctx.fillStyle = palette.text;
      ctx.font = `${Math.round(12 * scale)}px ui-monospace, SFMono-Regular, Menlo, monospace`;
      ctx.fillText(node.id, node.x + 30 * scale, node.y + boxH / 2 + 4 * scale);
    }
  });
}

const canvases = document.querySelectorAll(".mesh-canvas");
canvases.forEach((canvas) => {
  drawCanvas(canvas);
});

let resizeTimer;
window.addEventListener("resize", () => {
  window.clearTimeout(resizeTimer);
  resizeTimer = window.setTimeout(() => {
    canvases.forEach((canvas) => drawCanvas(canvas));
  }, 80);
});
