import { useEffect, useRef } from 'react';

/**
 * Canvas-based animated particle mesh background.
 * Floating nodes connected by lines when close — Calimero green palette.
 */
export function AnimatedBackground() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const GREEN = 'rgba(165, 255, 17,';
    const COUNT = 55;
    const MAX_DIST = 160;
    const SPEED = 0.28;

    let W, H, particles, animId;

    function resize() {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
    }

    function rand(min, max) {
      return Math.random() * (max - min) + min;
    }

    function makeParticle() {
      return {
        x: rand(0, W),
        y: rand(0, H),
        vx: rand(-SPEED, SPEED),
        vy: rand(-SPEED, SPEED),
        r: rand(1.2, 2.6),
        opacity: rand(0.25, 0.7),
      };
    }

    function init() {
      resize();
      particles = Array.from({ length: COUNT }, makeParticle);
    }

    function draw() {
      ctx.clearRect(0, 0, W, H);

      // update positions
      for (const p of particles) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < -20) p.x = W + 20;
        if (p.x > W + 20) p.x = -20;
        if (p.y < -20) p.y = H + 20;
        if (p.y > H + 20) p.y = -20;
      }

      // draw edges
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const a = particles[i];
          const b = particles[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < MAX_DIST) {
            const alpha = (1 - dist / MAX_DIST) * 0.18;
            ctx.beginPath();
            ctx.strokeStyle = `${GREEN} ${alpha})`;
            ctx.lineWidth = 0.8;
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      // draw nodes
      for (const p of particles) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `${GREEN} ${p.opacity})`;
        ctx.fill();
      }

      animId = requestAnimationFrame(draw);
    }

    init();
    draw();

    const onResize = () => {
      resize();
      // redistribute particles that are now out of bounds
      for (const p of particles) {
        if (p.x > W) p.x = rand(0, W);
        if (p.y > H) p.y = rand(0, H);
      }
    };
    window.addEventListener('resize', onResize);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', onResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        inset: 0,
        pointerEvents: 'none',
        zIndex: 0,
        opacity: 0.9,
      }}
    />
  );
}
