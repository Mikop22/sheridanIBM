"use client";

import type { ReactNode } from "react";
import { CircleHelp } from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

export function Hint({
  label,
  children,
  side = "top",
}: {
  label: string;
  children?: ReactNode;
  side?: "top" | "bottom" | "left" | "right";
}) {
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="inline-flex cursor-help items-center gap-1 border-b border-dotted border-[#8d8d8d]">
            {children ?? label}
            <CircleHelp size={12} className="text-[#6f6f6f]" aria-hidden />
            <span className="sr-only">{label}</span>
          </span>
        </TooltipTrigger>
        <TooltipContent side={side} className="max-w-xs text-left leading-5">
          {label}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
