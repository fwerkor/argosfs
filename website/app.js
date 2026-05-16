const canvas = document.getElementById("topology");
const ctx = canvas.getContext("2d");

function resize() {
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.floor(canvas.clientWidth * dpr);
  canvas.height = Math.floor(canvas.clientHeight * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}

const disks = Array.from({ length: 9 }, (_, index) => ({
  x: 0,
  y: 0,
  phase: index * 0.73,
  tier: index % 3
}));

function draw(time) {
  const w = canvas.clientWidth;
  const h = canvas.clientHeight;
  ctx.clearRect(0, 0, w, h);
  ctx.globalAlpha = 0.95;
  const cx = w * 0.64;
  const cy = h * 0.48;
  const radius = Math.min(w, h) * 0.28;
  disks.forEach((disk, index) => {
    const angle = (index / disks.length) * Math.PI * 2 + Math.sin(time / 2200 + disk.phase) * 0.05;
    disk.x = cx + Math.cos(angle) * radius;
    disk.y = cy + Math.sin(angle) * radius * 0.72;
  });
  ctx.lineWidth = 1;
  disks.forEach((disk, index) => {
    const next = disks[(index + 3) % disks.length];
    ctx.strokeStyle = "rgba(110, 231, 183, .22)";
    ctx.beginPath();
    ctx.moveTo(disk.x, disk.y);
    ctx.lineTo(next.x, next.y);
    ctx.stroke();
  });
  disks.forEach((disk, index) => {
    const colors = ["#ffce6b", "#6ee7b7", "#ff6f91"];
    ctx.fillStyle = colors[disk.tier];
    ctx.beginPath();
    ctx.arc(disk.x, disk.y, 10 + Math.sin(time / 700 + index) * 1.5, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = "rgba(247, 244, 234, .72)";
    ctx.font = "12px ui-monospace, monospace";
    ctx.fillText(`disk-${String(index).padStart(4, "0")}`, disk.x + 14, disk.y + 4);
  });
  requestAnimationFrame(draw);
}

resize();
window.addEventListener("resize", resize);
requestAnimationFrame(draw);
