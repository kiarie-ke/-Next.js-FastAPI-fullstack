import Link from "next/link";

export default function Home() {
  return (
    <main className="min-h-screen bg-gray-950 text-white">

      {/* Navbar */}
      <nav className="flex items-center justify-between px-8 py-5 border-b border-gray-800">
        <span className="text-amber-400 font-bold text-xl tracking-tight">Fullstack</span>
        <div className="flex items-center gap-4">
          <Link href="/contact" className="text-gray-400 hover:text-white text-sm transition">
            Contact
          </Link>
          <Link
            href="/login"
            className="px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-sm font-medium text-gray-300 border border-gray-700 transition"
          >
            Login
          </Link>
          <Link
            href="/register"
            className="px-4 py-2 rounded-lg bg-amber-600 hover:bg-indigo-500 text-sm font-semibold transition"
          >
            Get started
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <section className="flex flex-col items-center justify-center text-center px-6 py-32">
        <span className="text-xs font-semibold tracking-widest text-amber-400 uppercase mb-4">
          Welcome
        </span>
        <h1 className="text-5xl font-extrabold leading-tight max-w-2xl mb-6">
          Build something{" "}
          <span className="text-amber-400">great</span> today
        </h1>
        <p className="text-gray-400 text-lg max-w-xl mb-10">
          A simple, secure, and fast platform to get you started. Register an
          account and jump right in.
        </p>
        <div className="flex gap-4">
          <Link
            href="/register"
            className="px-6 py-3 rounded-lg bg-amber-600 hover:bg-indigo-500 font-semibold transition"
          >
            Create account
          </Link>
          <Link
            href="/login"
            className="px-6 py-3 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 font-medium transition"
          >
            Sign in
          </Link>
        </div>
      </section>

      {/* Features */}
      <section className="px-8 pb-24 max-w-4xl mx-auto">
        <h2 className="text-center text-2xl font-bold mb-10 text-gray-100">
          Why use this app?
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
          {[
            {
              // icon: "🔐",
              title: "Secure Auth",
              desc: "JWT-based authentication with bcrypt password hashing.",
            },
            {
              // icon: "⚡",
              title: "Fast API",
              desc: "Powered by FastAPI and SQLite for a lightweight backend.",
            },
            {
              // icon: "🎯",
              title: "Simple UI",
              desc: "Clean Next.js 14 frontend that's easy to extend.",
            },
          ].map((f) => (
            <div
              key={f.title}
              className="bg-gray-900 border border-gray-800 rounded-2xl p-6 text-center hover:border-indigo-500/50 transition"
            >
              <div className="text-3xl mb-3">{f.icon}</div>
              <h3 className="text-white font-semibold mb-2">{f.title}</h3>
              <p className="text-gray-400 text-sm">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-800 px-8 py-6 flex items-center justify-between text-gray-500 text-sm">
        <span>© {new Date().getFullYear()} Fullstack. All rights reserved.</span>
        <Link href="/contact" className="hover:text-white transition">
          Contact
        </Link>
      </footer>

    </main>
  );
}