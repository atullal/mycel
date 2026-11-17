# UI design

Apply these conventions when building or updating a Mycel interface.

- For nested rounded corners, subtract the inset from the outer radius, with a minimum inner radius of zero.
- Use translucent border colors so outlines blend with the underlying surface.
- Define palettes in OKLCH. Specify `in oklch` for gradients that interpolate colors.
- Match icon stroke weight to the adjacent text.
- Fade carousel edges with `mask: linear-gradient(90deg, transparent, black 15% 85%, transparent)`.
- When swapping icons, fade and blur the outgoing icon to `4px`. Respect reduced-motion preferences.
- In dark mode, use lighter surfaces to convey elevation.
- For viewport-height sections, use `100dvh`.
- Use `mix-blend-mode: multiply` for white-backed product shots on light surfaces.
