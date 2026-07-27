"use client";

import { useEffect, useState } from "react";
import axios from "axios";
import { useRouter } from "next/navigation";

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("token");

    if (!token) {
      router.push("/login");
      return;
    }

    axios
      .get("http://localhost:8000/me", {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => setUser(res.data))
      .catch(() => {
        localStorage.removeItem("token");
        router.push("/login");
      })
      .finally(() => setLoading(false));
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("token");
    router.push("/login");
  };

  if (loading) {
    return (
      <main className="min-h-screen flex items-center justify-center bg-gray-950">
        <p className="text-gray-400 text-sm animate-pulse">Loading...</p>
      </main>
    );
  }

  if (error) {
    return (
      <main className="min-h-screen flex items-center justify-center bg-gray-950">
        <p className="text-red-400 text-sm">{error}</p>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-2xl mx-auto">

        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <button
            onClick={handleLogout}
            className="px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-medium transition border border-gray-700"
          >
            Logout
          </button>
        </div>

        {/* User card */}
        <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800 shadow-xl">
          <div className="flex items-center gap-4 mb-6">
            <div className="w-14 h-14 rounded-full bg-amber-600 flex items-center justify-center text-white text-xl font-bold">
              {user?.username?.charAt(0).toUpperCase()}
            </div>
            <div>
              <p className="text-white font-semibold text-lg">{user?.username}</p>
              <p className="text-gray-400 text-sm">{user?.email}</p>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3">
            <div className="flex justify-between items-center px-4 py-3 rounded-lg bg-gray-800 border border-gray-700">
              <span className="text-gray-400 text-sm">User ID</span>
              <span className="text-white text-sm font-mono">#{user?.id}</span>
            </div>
            <div className="flex justify-between items-center px-4 py-3 rounded-lg bg-gray-800 border border-gray-700">
              <span className="text-gray-400 text-sm">Username</span>
              <span className="text-white text-sm">{user?.username}</span>
            </div>
            <div className="flex justify-between items-center px-4 py-3 rounded-lg bg-gray-800 border border-gray-700">
              <span className="text-gray-400 text-sm">Email</span>
              <span className="text-white text-sm">{user?.email}</span>
            </div>
          </div>

          {/* Action buttons */}
          <div className="grid grid-cols-2 gap-3 mt-6">
            <button
              onClick={() => router.push("/profile")}
              className="py-2.5 rounded-lg bg-amber-600 hover:bg-blue-500 text-white text-sm font-semibold transition"
            >
              Edit Profile
            </button>
            <button
              onClick={() => router.push("/admin")}
              className="py-2.5 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 text-sm font-medium transition"
            >
              Admin Panel
            </button>
          </div>

        </div>
      </div>
    </main>
  );
}