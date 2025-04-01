import Nav from "./components/Nav";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Home from "./pages/Home";
import About from "./pages/About";
import Contact from "./pages/Contact";

export default function App() {
  const hrefs = [
    { label: "Home", href: "/" },
    { label: "About", href: "/about" },
    { label: "Contact", href: "/contact" },
  ];

  return (
    <BrowserRouter>
      <div className="h-screen flex flex-col p-2 gap-2">
        <Nav items={hrefs} />
        <main className="h-full border p-4">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/about" element={<About />} />
            <Route path="/contact" element={<Contact />} />
          </Routes>
        </main>
      </div>
      <footer>
        <p className="text-center text-sm text-gray-500">
          &copy; 2021 Elliot. All rights reserved.
        </p>
      </footer>
    </BrowserRouter>
  );
}
