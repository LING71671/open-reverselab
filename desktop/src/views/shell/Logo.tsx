interface LogoProps {
  size?: number;
  className?: string;
}

/**
 * ReverseLab Monolith Fault-Line Logo (断层单体 / 秩序破坏).
 * A stark geometric monolith cleanly severed and offset by an angular 45°
 * fault fissure, representing the deconstruction of compiled order.
 */
export function Logo({ size = 16, className = "" }: LogoProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`shrink-0 transition-transform duration-200 hover:scale-110 cursor-pointer ${className}`}
    >
      {/* Upper-Left Monolith Fragment */}
      <path
        d="M3 5 H18.5 L24.5 0 L15 13 L8 21.5 H3 Z"
        fill="currentColor"
      />
      {/* Lower-Right Monolith Fragment (Offset Fault) */}
      <path
        d="M29 27 H13.5 L7.5 32 L17 19 L24 10.5 H29 Z"
        fill="currentColor"
      />
    </svg>
  );
}
