import { Link } from "react-router-dom";

export interface NavProps {
  items: {
    label: string;
    href: string;
  }[];
}

export default function Nav(props: NavProps) {
  return (
    <nav className="flex justify-between items-center p-1 rounded-xl shadow-lg shadow-neutral-500/50 bg-neutral-200 select-none">
      <img src="./logo.svg" alt="Elliot logo" className="h-14" />
      <ul>
        {props.items.map((item, index) => (
          <li key={index} className="inline-block mx-2">
            <Link
              to={item.href}
              className="hover:text-blue-600 transition-colors"
            >
              {item.label}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}
