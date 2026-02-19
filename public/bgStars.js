// Canvas-based constellation background
(() => {
  const canvas = document.getElementById('bgStars');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const reduceMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  let width = 0;
  let height = 0;
  let dpr = window.devicePixelRatio || 1;
  let particles = [];
  let colors = [];
  let animationId = null;

  const hexToRgb = (hex) => {
    const clean = hex.replace('#', '').trim();
    if (clean.length !== 6) return null;
    const num = parseInt(clean, 16);
    if (Number.isNaN(num)) return null;
    return { r: (num >> 16) & 255, g: (num >> 8) & 255, b: num & 255 };
  };

  const getAccentColors = () => {
    const styles = getComputedStyle(document.documentElement);
    const fallback = ['#5aa9ff', '#7fd1ff', '#3c6fff'];
    return [
      styles.getPropertyValue('--accent').trim() || fallback[0],
      styles.getPropertyValue('--accent-2').trim() || fallback[1],
      styles.getPropertyValue('--accent-3').trim() || fallback[2],
    ];
  };

  const resize = () => {
    width = window.innerWidth;
    height = window.innerHeight;
    dpr = window.devicePixelRatio || 1;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    colors = getAccentColors();
    spawnParticles();
    drawFrame(0);
  };

  const spawnParticles = () => {
    const area = Math.max(width * height, 1);
    const count = Math.min(180, Math.max(80, Math.floor(area / 12000)));
    particles = Array.from({ length: count }).map(() => {
      const color = colors[Math.floor(Math.random() * colors.length)];
      return {
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.15,
        vy: (Math.random() - 0.5) * 0.15,
        radius: 0.8 + Math.random() * 1.4,
        baseAlpha: 0.35 + Math.random() * 0.45,
        twinkleOffset: Math.random() * Math.PI * 2,
        twinkleSpeed: 0.004 + Math.random() * 0.006,
        color,
      };
    });
  };

  const driftParticles = () => {
    particles.forEach((p) => {
      p.vx += (Math.random() - 0.5) * 0.002;
      p.vy += (Math.random() - 0.5) * 0.002;
      p.vx = Math.max(-0.12, Math.min(0.12, p.vx));
      p.vy = Math.max(-0.12, Math.min(0.12, p.vy));
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < -20) p.x = width + 20;
      if (p.x > width + 20) p.x = -20;
      if (p.y < -20) p.y = height + 20;
      if (p.y > height + 20) p.y = -20;
    });
  };

  const drawConnections = () => {
    const maxDist = Math.min(160, Math.max(110, width * 0.12));
    const lineRgb = hexToRgb(colors[1] || colors[0]) || { r: 90, g: 169, b: 255 };
    for (let i = 0; i < particles.length; i += 1) {
      for (let j = i + 1; j < particles.length; j += 1) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < maxDist) {
          const alpha = (1 - dist / maxDist) * 0.25;
          ctx.strokeStyle = `rgba(${lineRgb.r}, ${lineRgb.g}, ${lineRgb.b}, ${alpha})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }
  };

  const drawParticles = (time) => {
    particles.forEach((p) => {
      const rgb = hexToRgb(p.color) || { r: 90, g: 169, b: 255 };
      const twinkle = Math.sin(time * p.twinkleSpeed + p.twinkleOffset) * 0.15;
      const alpha = Math.max(0.1, p.baseAlpha + twinkle);
      ctx.fillStyle = `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${alpha})`;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fill();
    });
  };

  const drawFrame = (time) => {
    ctx.clearRect(0, 0, width, height);
    drawConnections();
    drawParticles(time);
  };

  const animate = (time) => {
    drawFrame(time);
    if (!reduceMotionQuery.matches) {
      driftParticles();
      animationId = requestAnimationFrame(animate);
    }
  };

  const start = () => {
    if (animationId) cancelAnimationFrame(animationId);
    if (reduceMotionQuery.matches) {
      drawFrame(0);
      return;
    }
    animationId = requestAnimationFrame(animate);
  };

  const handleMotionChange = () => start();

  const observer = new MutationObserver(() => {
    colors = getAccentColors();
  });
  observer.observe(document.body, { attributes: true, attributeFilter: ['class'] });

  window.addEventListener('resize', () => {
    resize();
    start();
  });
  if (reduceMotionQuery.addEventListener) {
    reduceMotionQuery.addEventListener('change', handleMotionChange);
  }

  resize();
  start();
})();
