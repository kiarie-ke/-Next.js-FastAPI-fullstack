"use client";

import { useEffect, useState } from "react";
import axios from "axios";
import { useRouter } from "next/navigation";

export default function ProfilePage() {
  const router = useRouter();
  const [user, setUser] = useState(null);
  const [username, setUsername] = useState("");
  const [passwords, setPasswords] = useState({ current_password: "", new_password: "" });
  const [profileMsg, setProfileMsg] = useState({ text: "", error: false });
  const [passwordMsg, setPasswordMsg] = useState({ text: "", error: false });
  const [loading, setLoading] = useState(true);

  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    if (!token) { router.push("/login"); return; }
    axios.get("http://localhost:8000/me", { headers })
      .then((res) => { setUser(res.data); setUsername(res.data.username); })
      .catch(() => { localStorage.removeItem("token"); router.push("/login"); })
      .finally(() => setLoading(false));
  }, []);

  const handleUpdateProfile = async (e) => {
    e.preventDefault();
    try {
      await axios.put("http://localhost:8000/me/update", { username }, { headers });
      setProfileMsg({ text: "Username updated successfully.", error: false });
      setUser((prev) => ({ ...prev, username }));
    } catch (err) {
      setProfileMsg({ text: err.response?.data?.detail || "Update failed.", error: true });
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    try {
      await axios.put("http://localhost:8000/me/change-password", passwords, { headers });
      setPasswordMsg({ text: "Password changed successfully.", error: false });
      setPasswords({ current_password: "", new_password: "" });
    } catch (err) {
      setPasswordMsg({ text: err.response?.data?.detail || "Change failed.", error: true });
    }
  };

  if (loading) return (
    <main className="min-h-screen flex items-center justify-center bg-gray-950">
      <p className="text-gray-400 text-sm animate-pulse">Loading...</p>
    </main>
  );

  return (
    <main className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-lg mx-auto space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">Profile</h1>
          <button
            onClick={() => router.push("/dashboard")}
            className="text-sm text-gray-400 hover:text-white transition"
          >
            ← Back
          </button>
        </div>

        {/* Avatar */}
        <div className="flex items-center gap-4 bg-gray-900 border border-gray-800 rounded-2xl p-5">
          <div className="w-14 h-14 rounded-full bg-indigo-600 flex items-center justify-center text-white text-xl font-bold">
            {user?.username?.charAt(0).toUpperCase()}
          </div>
          <div>
            <p className="text-white font-semibold">{user?.username}</p>
            <p className="text-gray-400 text-sm">{user?.email}</p>
          </div>
        </div>

        {/* Update Username */}
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
          <h2 className="text-white font-semibold mb-4">Update Username</h2>
          {profileMsg.text && (
            <p className={`text-sm mb-3 ${profileMsg.error ? "text-red-400" : "text-green-400"}`}>
              {profileMsg.text}
            </p>
          )}
          <form onSubmit={handleUpdateProfile} className="space-y-3">
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              placeholder="New username"
              className="w-full px-4 py-2.5 rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 focus:outline-none focus:border-indigo-500 transition"
            />
            <button
              type="submit"
              className="w-full py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold transition"
            >
              Save changes
            </button>
          </form>
        </div>

        {/* Change Password */}
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
          <h2 className="text-white font-semibold mb-4">Change Password</h2>
          {passwordMsg.text && (
            <p className={`text-sm mb-3 ${passwordMsg.error ? "text-red-400" : "text-green-400"}`}>
              {passwordMsg.text}
            </p>
          )}
          <form onSubmit={handleChangePassword} className="space-y-3">
            <input
              type="password"
              value={passwords.current_password}
              onChange={(e) => setPasswords({ ...passwords, current_password: e.target.value })}
              required
              placeholder="Current password"
              className="w-full px-4 py-2.5 rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 focus:outline-none focus:border-indigo-500 transition"
            />
            <input
              type="password"
              value={passwords.new_password}
              onChange={(e) => setPasswords({ ...passwords, new_password: e.target.value })}
              required
              placeholder="New password"
              className="w-full px-4 py-2.5 rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 focus:outline-none focus:border-indigo-500 transition"
            />
            <button
              type="submit"
              className="w-full py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold transition"
            >
              Change password
            </button>
          </form>
        </div>

      </div>
    </main>
  );
}