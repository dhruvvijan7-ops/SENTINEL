import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { userService } from "@/services/userService";
import type { UserRecord } from "@/services/userService";

const ROLE_OPTIONS = [
  { value: "", label: "All roles" },
  { value: "admin", label: "Admin" },
  { value: "analyst", label: "Analyst" },
  { value: "viewer", label: "Viewer" },
];

const ACTIVE_OPTIONS = [
  { value: "", label: "All status" },
  { value: "true", label: "Active" },
  { value: "false", label: "Inactive" },
];

export default function UsersPage() {
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [activeFilter, setActiveFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newUser, setNewUser] = useState({ name: "", email: "", password: "", role: "analyst" });

  const loadUsers = useCallback(async () => {
    setLoading(true);
    try {
      const data = await userService.getUsers({
        page,
        page_size: 10,
        search: search || undefined,
        role: roleFilter || undefined,
        is_active: activeFilter ? activeFilter === "true" : undefined,
      });
      setUsers(data.items);
      setTotal(data.total);
      setTotalPages(data.total_pages);
    } catch {
      toast.error("Failed to load users.");
    } finally {
      setLoading(false);
    }
  }, [page, search, roleFilter, activeFilter]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const handleSearch = () => {
    setPage(1);
    setSearch(searchInput);
  };

  const handleToggleActive = async (user: UserRecord) => {
    setActionLoading(user.id);
    try {
      await userService.updateUser(user.id, { is_active: !user.is_active });
      toast.success(user.is_active ? `${user.email} deactivated` : `${user.email} activated`);
      loadUsers();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      toast.error(msg);
    } finally {
      setActionLoading(null);
    }
  };

  const handleChangeRole = async (user: UserRecord, newRole: string) => {
    setActionLoading(user.id);
    try {
      await userService.updateUser(user.id, { role: newRole });
      toast.success(`${user.email} is now ${newRole}.`);
      loadUsers();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      toast.error(msg);
    } finally {
      setActionLoading(null);
    }
  };

  const handleCreateUser = async () => {
    setCreating(true);
    try {
      await userService.createUser(newUser);
      toast.success(`${newUser.email} created.`);
      setShowCreate(false);
      setNewUser({ name: "", email: "", password: "", role: "analyst" });
      loadUsers();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      toast.error(msg);
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="mx-auto w-full max-w-[1100px] space-y-6 p-4 md:p-6 lg:p-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100">User Management</h1>
          <p className="text-slate-400 mt-1">{total} users total</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setShowCreate(true)}>
          Create User
        </Button>
      </div>

      {/* Filters */}
      <div className="rounded-2xl border bg-card p-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <Input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            placeholder="Search name or email…"
            className="flex-1"
          />
          <Button variant="outline" onClick={handleSearch}>Search</Button>

          <select
            value={roleFilter}
            onChange={(e) => { setRoleFilter(e.target.value); setPage(1); }}
            className="h-8 rounded-lg border border-border bg-input px-2 text-sm text-foreground"
          >
            {ROLE_OPTIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>

          <select
            value={activeFilter}
            onChange={(e) => { setActiveFilter(e.target.value); setPage(1); }}
            className="h-8 rounded-lg border border-border bg-input px-2 text-sm text-foreground"
          >
            {ACTIVE_OPTIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-2xl border bg-card">
        {loading ? (
          <div className="p-8 text-center text-slate-400">Loading…</div>
        ) : users.length === 0 ? (
          <div className="p-8 text-center text-slate-400">No users found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-slate-400">
                  <th className="text-left px-4 py-3 font-medium">Name</th>
                  <th className="text-left px-4 py-3 font-medium">Email</th>
                  <th className="text-left px-4 py-3 font-medium">Role</th>
                  <th className="text-left px-4 py-3 font-medium">Status</th>
                  <th className="text-right px-4 py-3 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="border-b border-slate-800 hover:bg-slate-800/50">
                    <td className="px-4 py-3 text-slate-100 font-medium">{u.name}</td>
                    <td className="px-4 py-3 text-slate-300">{u.email}</td>
                    <td className="px-4 py-3">
                      <select
                        value={u.role}
                        onChange={(e) => handleChangeRole(u, e.target.value)}
                        disabled={actionLoading === u.id}
                        className="h-7 rounded border border-border bg-input px-2 text-xs text-foreground disabled:opacity-50"
                      >
                        <option value="admin">admin</option>
                        <option value="analyst">analyst</option>
                        <option value="viewer">viewer</option>
                      </select>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${u.is_active ? "text-emerald-400 bg-emerald-500/10" : "text-slate-500 bg-slate-700/30"}`}>
                        {u.is_active ? "Active" : "Inactive"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleToggleActive(u)}
                        disabled={actionLoading === u.id}
                        className={u.is_active ? "text-amber-400 hover:bg-amber-500/10" : "text-emerald-400 hover:bg-emerald-500/10"}
                      >
                        {actionLoading === u.id ? "…" : u.is_active ? "Deactivate" : "Activate"}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-700">
            <span className="text-sm text-slate-400">
              Page {page} of {totalPages}
            </span>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page <= 1}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Create User Modal */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => setShowCreate(false)}>
          <div className="bg-card border rounded-2xl p-6 w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-slate-100 mb-4">Create User</h2>
            <div className="space-y-3">
              <label className="flex flex-col gap-1">
                <span className="text-xs text-slate-400">Name</span>
                <input
                  value={newUser.name}
                  onChange={(e) => setNewUser({ ...newUser, name: e.target.value })}
                  className="h-9 rounded-lg border border-border bg-input px-2 text-sm text-foreground"
                />
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-xs text-slate-400">Email</span>
                <input
                  type="email"
                  value={newUser.email}
                  onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                  className="h-9 rounded-lg border border-border bg-input px-2 text-sm text-foreground"
                />
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-xs text-slate-400">Password</span>
                <input
                  type="password"
                  value={newUser.password}
                  onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                  className="h-9 rounded-lg border border-border bg-input px-2 text-sm text-foreground"
                />
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-xs text-slate-400">Role</span>
                <select
                  value={newUser.role}
                  onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                  className="h-9 rounded-lg border border-border bg-input px-2 text-sm text-foreground"
                >
                  <option value="admin">Admin</option>
                  <option value="analyst">Analyst</option>
                </select>
              </label>
            </div>
            <div className="flex justify-end gap-2 mt-5">
              <Button variant="ghost" size="sm" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button size="sm" onClick={handleCreateUser} disabled={creating || !newUser.name || !newUser.email || !newUser.password}>
                {creating ? "Creating…" : "Create"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
