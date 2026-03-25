import { useState, useRef, useEffect } from 'react';
import './CustomSelect.css';

/**
 * Custom styled dropdown to replace native <select>.
 * Accepts same shape as before: options array of { value, label }.
 */
export function CustomSelect({ id, name, options, defaultValue = '', disabled = false, onChange }) {
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState(defaultValue);
  const ref = useRef(null);

  const current = options.find((o) => o.value === selected) || options[0];

  useEffect(() => {
    function onClickOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, []);

  function pick(value) {
    setSelected(value);
    setOpen(false);
    onChange?.(value);
  }

  return (
    <div
      className={`cselect${open ? ' cselect--open' : ''}${disabled ? ' cselect--disabled' : ''}`}
      ref={ref}
      id={id}
    >
      {/* hidden input so form serialisation still works */}
      <input type="hidden" name={name} value={selected} />

      <button
        type="button"
        className="cselect-trigger"
        onClick={() => !disabled && setOpen((v) => !v)}
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <span className="cselect-value">{current.label}</span>
        <span className={`cselect-arrow${open ? ' cselect-arrow--up' : ''}`}>▾</span>
      </button>

      {open && (
        <ul className="cselect-menu" role="listbox">
          {options.map((o) => (
            <li
              key={o.value ?? '__empty'}
              role="option"
              aria-selected={o.value === selected}
              className={`cselect-option${o.value === selected ? ' cselect-option--active' : ''}`}
              onClick={() => pick(o.value)}
            >
              {o.value === selected && <span className="cselect-check">✓</span>}
              {o.label}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
