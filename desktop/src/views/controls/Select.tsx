import * as Primitive from "@radix-ui/react-select";
import { Check, ChevronDown, ChevronUp } from "lucide-react";

export interface SelectOption { value: string; label: string; disabled?: boolean }
interface SelectProps {
  value: string;
  onChange: (value: string) => void;
  options: SelectOption[];
  label: string;
  placeholder?: string;
  disabled?: boolean;
  id?: string;
  className?: string;
}

/** Shared menu, including keyboard navigation, typeahead and focus restoration. */
export function Select({ value, onChange, options, label, placeholder = "请选择", disabled, id, className = "" }: SelectProps) {
  return <Primitive.Root value={value} onValueChange={onChange} disabled={disabled}>
    <Primitive.Trigger id={id} className={`select-trigger ${className}`} aria-label={label}>
      <Primitive.Value placeholder={placeholder} />
      <Primitive.Icon asChild><ChevronDown size={15} /></Primitive.Icon>
    </Primitive.Trigger>
    <Primitive.Portal>
      <Primitive.Content className="select-menu" position="popper" sideOffset={5} collisionPadding={12}>
        <Primitive.ScrollUpButton className="select-scroll"><ChevronUp size={14} /></Primitive.ScrollUpButton>
        <Primitive.Viewport className="select-options">
          {options.map(option => <Primitive.Item className="select-option" key={option.value} value={option.value} disabled={option.disabled}>
            <Primitive.ItemText>{option.label}</Primitive.ItemText>
            <Primitive.ItemIndicator className="select-check"><Check size={14} /></Primitive.ItemIndicator>
          </Primitive.Item>)}
        </Primitive.Viewport>
        <Primitive.ScrollDownButton className="select-scroll"><ChevronDown size={14} /></Primitive.ScrollDownButton>
      </Primitive.Content>
    </Primitive.Portal>
  </Primitive.Root>;
}
