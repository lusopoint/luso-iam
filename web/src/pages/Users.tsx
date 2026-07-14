import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Input,
  Loading,
  PageHeader,
  Pagination,
  Select,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  useToast,
} from "@lusopoint/luso-ui";
import { Search, UserPlus } from "lucide-react";
import { ErrorState } from "../components/States";
import { ApiError, api } from "../lib/api";
import type { AdminUser } from "../lib/types";
import { formatDateTime } from "../lib/util";
import NewUserDialog from "./NewUserDialog";

const PAGE_SIZE = 25;

const Users = () => {
  const toast = useToast();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [offset, setOffset] = useState(0);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [newOpen, setNewOpen] = useState(false);
  // bumping refetchTick re runs the effect, we use this instead of putting
  // `search` directly in the deps so typing doesn't fire a request per keystroke
  const [refetchTick, setRefetchTick] = useState(0);

  useEffect(() => {
    const ctrl = new AbortController();
    setLoading(true);
    api
      .listUsers(
        { search, status: statusFilter, limit: PAGE_SIZE, offset },
        ctrl.signal,
      )
      .then((res) => {
        setUsers(res.users);
        setTotal(res.total);
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (ctrl.signal.aborted) return;
        setError(err instanceof ApiError ? err : new ApiError({ type: "about:blank", title: "Error", status: 0, detail: String(err) }));
        setLoading(false);
      });
    return () => ctrl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter, offset, refetchTick]);

  const submitSearch = () => {
    setOffset(0);
    setRefetchTick((n) => n + 1);
  };

  // luso-ui Pagination is page-based, the API is offset-based
  // translate at the boundary rather than reworking the query contract
  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <>
      <PageHeader
        title="Users"
        subtitle={`${total} ${total === 1 ? "user" : "users"} in total.`}
        actions={
          <Button onClick={() => setNewOpen(true)} className="gap-2">
            <UserPlus size={16} />
            New user
          </Button>
        }
      />

      <NewUserDialog
        open={newOpen}
        onClose={() => setNewOpen(false)}
        onCreated={() => {
          setOffset(0);
          setRefetchTick((n) => n + 1);
          toast.success("User created.");
        }}
      />

      <Card noHover variant="low" className="mb-6 p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="grow basis-64">
            <Input
              label="Search"
              placeholder="email or username"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  submitSearch();
                }
              }}
            />
          </div>
          <div className="basis-40">
            <Select
              label="Status"
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setOffset(0);
              }}
            >
              <option value="">Any</option>
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
              <option value="pending">Pending</option>
            </Select>
          </div>
          <Button onClick={submitSearch} className="h-12 gap-2">
            <Search size={16} />
            Search
          </Button>
        </div>
      </Card>

      {loading && <Loading label="Loading users…" />}
      {error && <ErrorState error={error} />}
      {!loading && !error && users.length === 0 && (
        <EmptyState
          title="No users match these filters."
          description="Try clearing the search or status filter."
        />
      )}
      {!loading && !error && users.length > 0 && (
        <>
          {/* mobile */}
          <ul className="space-y-3 md:hidden">
            {users.map((u) => (
              <li key={u.id}>
                <Link to={`/users/${u.id}`} className="block">
                  <Card noHover className="p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-bold text-on-surface">
                          {u.email || u.username || u.id.slice(0, 8)}
                        </p>
                        {u.display_name && (
                          <p className="truncate text-xs text-on-surface-variant">
                            {u.display_name}
                          </p>
                        )}
                      </div>
                      <div className="flex shrink-0 flex-col items-end gap-1">
                        <StatusBadge status={u.status} />
                        {u.is_admin && <Badge status="in_progress" label="admin" />}
                      </div>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-x-3 gap-y-1 text-xs text-on-surface-variant">
                      <span>Last&nbsp;login&nbsp;{formatDateTime(u.last_login_at)}</span>
                      <span>·</span>
                      <span>Joined&nbsp;{formatDateTime(u.created_at)}</span>
                    </div>
                  </Card>
                </Link>
              </li>
            ))}
          </ul>

          {/* desktop */}
          <Card noHover className="hidden overflow-hidden md:block">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Email / Username</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Admin</TableHead>
                  <TableHead>Last login</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell>
                      <Link
                        to={`/users/${u.id}`}
                        className="font-semibold text-primary hover:underline"
                      >
                        {u.email || u.username || u.id.slice(0, 8)}
                      </Link>
                      {u.display_name && (
                        <div className="text-xs text-on-surface-variant">
                          {u.display_name}
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={u.status} />
                    </TableCell>
                    <TableCell>
                      {u.is_admin ? (
                        <Badge status="in_progress" label="admin" />
                      ) : (
                        <span className="text-on-surface-variant/40">-</span>
                      )}
                    </TableCell>
                    <TableCell>{formatDateTime(u.last_login_at)}</TableCell>
                    <TableCell>{formatDateTime(u.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>

          <div className="mt-6 flex flex-col items-center justify-between gap-4 sm:flex-row">
            <span className="text-xs font-bold uppercase tracking-widest text-on-surface-variant">
              Showing {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
            </span>
            {totalPages > 1 && (
              <Pagination
                currentPage={page}
                totalPages={totalPages}
                onPageChange={(p) => setOffset((p - 1) * PAGE_SIZE)}
              />
            )}
          </div>
        </>
      )}
    </>
  );
}

export const StatusBadge = ({ status }: { status: string }) => <Badge status={status === "active" ? "operational" : status === "disabled" ? "critical" : "pending"} label={status} />;

export default Users
