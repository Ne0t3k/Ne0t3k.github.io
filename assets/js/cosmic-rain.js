(() => {
  const canvas = document.getElementById("cosmic-rain");
  const context = canvas?.getContext("2d");

  if (!context) {
    return;
  }

  const motionPreference = window.matchMedia(
    "(prefers-reduced-motion: reduce)"
  );

  const frameInterval = 1000 / 30;
  const symbolSize = 22;

  let columns = [];
  let width = 0;
  let height = 0;
  let animationFrame = null;
  let lastFrame = 0;

  function line(points) {
    context.beginPath();
    context.moveTo(points[0][0], points[0][1]);

    for (let index = 1; index < points.length; index++) {
      context.lineTo(points[index][0], points[index][1]);
    }

    context.stroke();
  }

  function circle(x, y, radius) {
    context.beginPath();
    context.arc(x, y, radius, 0, Math.PI * 2);
    context.stroke();
  }

  function dot(x, y) {
    context.beginPath();
    context.arc(x, y, 1.2, 0, Math.PI * 2);
    context.fill();
  }

  const symbols = [
    // Sello ramificado: evocación arcana, sin reproducir un signo histórico.
    () => {
      line([[0, 9], [0, -8], [-6, -3]]);
      line([[0, -4], [6, -9]]);
      line([[0, 2], [7, 5]]);
      line([[0, 6], [-5, 9]]);
      dot(6, -9);
    },

    // Ojo dentro de un circuito abierto.
    () => {
      line([[-9, 0], [-4, -5], [4, -5], [9, 0]]);
      line([[-9, 0], [-4, 5], [4, 5], [9, 0]]);
      circle(0, 0, 2);
      line([[0, -9], [0, -6]]);
      dot(0, 9);
    },

    // Umbral angular con un nodo central.
    () => {
      line([[-8, 8], [-8, -5], [0, -9], [8, -5], [8, 8]]);
      line([[-4, 8], [-4, 1], [0, -2], [4, 1], [4, 8]]);
      dot(0, 3);
    },

    // Señal fragmentada.
    () => {
      line([[-9, -7], [-3, -7], [0, -3], [0, 3]]);
      line([[9, 7], [3, 7], [0, 3]]);
      line([[-8, 6], [-4, 2]]);
      line([[8, -6], [4, -2]]);
      dot(-9, 6);
      dot(9, -6);
    },

    // Órbita incompleta y núcleo desplazado.
    () => {
      context.beginPath();
      context.arc(0, 0, 8, -0.8, Math.PI * 1.45);
      context.stroke();

      line([[-3, 0], [2, -4], [5, 1]]);
      dot(2, -4);
      line([[7, -9], [7, -5]]);
    }
  ];

  function resize() {
    const pixelRatio = Math.min(window.devicePixelRatio || 1, 2);

    width = window.innerWidth;
    height = window.innerHeight;

    canvas.width = Math.round(width * pixelRatio);
    canvas.height = Math.round(height * pixelRatio);

    context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    context.clearRect(0, 0, width, height);

    const spacing = width < 760 ? 105 : 85;
    const count = Math.ceil(width / spacing);

    columns = Array.from({ length: count }, (_, index) => ({
      x: index * spacing + Math.random() * 20,
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

    for (const column of columns) {
      if (!column.active) {
        continue;
      }

      context.save();
      context.translate(column.x, column.y);
      context.lineWidth = 1.15;
      context.lineCap = "round";
      context.lineJoin = "round";

      const color =
        Math.random() > 0.94
          ? "rgba(199, 146, 255, 0.28)"
          : "rgba(56, 232, 255, 0.21)";

      context.strokeStyle = color;
      context.fillStyle = color;

      const symbol = symbols[Math.floor(Math.random() * symbols.length)];
      symbol();

      context.restore();

      column.y += column.speed * symbolSize;

      if (column.y > height + symbolSize * 8) {
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
