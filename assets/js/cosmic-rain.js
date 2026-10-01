(() => {
  const canvas = document.getElementById("cosmic-rain");
  const context = canvas?.getContext("2d");

  if (!context) {
    return;
  }

  const motionPreference = window.matchMedia(
    "(prefers-reduced-motion: reduce)"
  );

  const glyphs = ["⟁", "⟐", "⌬", "⊗", "⋔", "☽", "∿", "⟡"];
  const fontSize = 19;
  const frameInterval = 1000 / 30;

  let columns = [];
  let width = 0;
  let height = 0;
  let animationFrame = null;
  let lastFrame = 0;

  function resize() {
    const pixelRatio = Math.min(window.devicePixelRatio || 1, 2);

    width = window.innerWidth;
    height = window.innerHeight;

    canvas.width = Math.round(width * pixelRatio);
    canvas.height = Math.round(height * pixelRatio);

    context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    context.clearRect(0, 0, width, height);

    const spacing = width < 760 ? 95 : 75;
    const count = Math.ceil(width / spacing);

    columns = Array.from({ length: count }, (_, index) => ({
      x: index * spacing + Math.random() * 18,
      y: -Math.random() * height,
      speed: 0.35 + Math.random() * 0.45,
      active: Math.random() > 0.35
    }));
  }

  function draw(timestamp) {
    animationFrame = window.requestAnimationFrame(draw);

    if (timestamp - lastFrame < frameInterval) {
      return;
    }

    lastFrame = timestamp;

    context.save();
    context.globalCompositeOperation = "destination-out";
    context.fillStyle = "rgba(0, 0, 0, 0.085)";
    context.fillRect(0, 0, width, height);
    context.restore();

    context.font = `${fontSize}px "Space Mono", monospace`;
    context.textAlign = "center";

    for (const column of columns) {
      if (!column.active) {
        continue;
      }

      const glyph = glyphs[Math.floor(Math.random() * glyphs.length)];

      context.fillStyle =
        Math.random() > 0.94
          ? "rgba(199, 146, 255, 0.24)"
          : "rgba(56, 232, 255, 0.18)";

      context.fillText(glyph, column.x, column.y);
      column.y += column.speed * fontSize;

      if (column.y > height + fontSize * 8) {
        column.y = -Math.random() * height * 0.5;
        column.active = Math.random() > 0.25;
      }
    }
  }

  function stop() {
    if (animationFrame !== null) {
      window.cancelAnimationFrame(animationFrame);
      animationFrame = null;
    }

    context.clearRect(0, 0, width, height);
  }

  function updateAnimation() {
    if (motionPreference.matches || document.hidden) {
      stop();
      return;
    }

    if (animationFrame === null) {
      lastFrame = 0;
      animationFrame = window.requestAnimationFrame(draw);
    }
  }

  window.addEventListener("resize", resize);
  document.addEventListener("visibilitychange", updateAnimation);
  motionPreference.addEventListener("change", updateAnimation);

  resize();
  updateAnimation();
})();
