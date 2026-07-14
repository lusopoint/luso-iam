import { useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  EmptyState,
  Input,
  Loading,
  PageHeader,
  TagInput,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  useConfirm,
  useToast,
} from "@lusopoint/luso-ui";
import { Plus } from "lucide-react";

import { ErrorState } from "../components/States";
import { ApiError, api } from "../lib/api";
import type { CASService, CreateCASServiceRequest } from "../lib/types";
import { formatDateTime } from "../lib/util";

const CASServices = () => {
  const toast = useToast();
  const confirm = useConfirm();
  const [services, setServices] = useState<CASService[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [adding, setAdding] = useState(false);

  useEffect(() => { refresh(); }, []);

  const refresh = () => {
    setLoading(true);
    api.listCASServices()
      .then((r) => { setServices(r.services); setError(null); setLoading(false); })
      .catch((err) => {
        setError(err instanceof ApiError ? err : new ApiError({ type: "about:blank", title: "Error", status: 0, detail: String(err) }));
        setLoading(false);
      });
  }

  const toggle = async (s: CASService) => {
    try {
      const updated = await api.updateCASService(s.id, { enabled: !s.enabled });
      setServices((list) => list.map((x) => x.id === s.id ? updated : x));
      toast.success(updated.enabled ? `Enabled "${s.name}".` : `Disabled "${s.name}".`);
    } catch (err) {
      toast.error("Could not update service.", err instanceof ApiError ? err.message : String(err));
    }
  }

  const remove = async (s: CASService) => {
    const ok = await confirm({
      title: `Delete "${s.name}"?`,
      message: "Active CAS tickets will continue to validate until they expire (typically 60s).",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!ok) return;
    try {
      await api.deleteCASService(s.id);
      setServices((list) => list.filter((x) => x.id !== s.id));
      toast.success(`Deleted "${s.name}".`);
    } catch (err) {
      toast.error("Could not delete service.", err instanceof ApiError ? err.message : String(err));
    }
  }

  const registerButton = (
    <Button onClick={() => setAdding(true)} className="gap-2">
      <Plus size={16} />
      Register service
    </Button>
  );

  return (
    <>
      <PageHeader
        title="CAS services"
        subtitle="Applications allowed to use the CAS authentication protocol."
        actions={!adding && registerButton}
      />

      {adding && (
        <AddForm
          onCancel={() => setAdding(false)}
          onCreated={() => { setAdding(false); refresh(); }}
        />
      )}

      {loading && <Loading label="Loading services…" />}
      {error && <ErrorState error={error} />}
      {!loading && !error && services.length === 0 && !adding && (
        <EmptyState
          title="No CAS services registered."
          description="Register your first service to enable CAS-protocol logins."
          action={registerButton}
        />
      )}

      {!loading && !error && services.length > 0 && (
        <>
          {/* Mobile: cards with the most important fields surfaced inline. */}
          <ul className="space-y-3 md:hidden">
            {services.map((s) => (
              <li key={s.id}>
                <Card noHover className="p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-bold text-on-surface">{s.name}</p>
                      {s.description && (
                        <p className="truncate text-xs text-on-surface-variant">
                          {s.description}
                        </p>
                      )}
                    </div>
                    <Badge
                      status={s.enabled ? "operational" : "critical"}
                      label={s.enabled ? "enabled" : "disabled"}
                    />
                  </div>

                  <code className="mt-3 block break-all rounded-lg bg-surface-container-lowest px-3 py-2 font-mono text-xs text-on-surface">
                    {s.service_url_pattern}
                  </code>

                  {s.released_attributes.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {s.released_attributes.map((a) => (
                        <Badge key={a} status="pending" label={a} />
                      ))}
                    </div>
                  )}

                  <div className="mt-4 flex items-center justify-between">
                    <span className="text-xs text-on-surface-variant">
                      {formatDateTime(s.created_at)}
                    </span>
                    <div className="flex gap-1">
                      <Button variant="ghost" size="sm" onClick={() => toggle(s)}>
                        {s.enabled ? "Disable" : "Enable"}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => remove(s)}
                        className="text-error hover:bg-error/10"
                      >
                        Delete
                      </Button>
                    </div>
                  </div>
                </Card>
              </li>
            ))}
          </ul>

          {/* Desktop: table. */}
          <Card noHover className="hidden overflow-hidden md:block">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>URL pattern</TableHead>
                  <TableHead>Released attributes</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {services.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <div className="font-bold text-on-surface">{s.name}</div>
                      {s.description && (
                        <div className="text-xs text-on-surface-variant">{s.description}</div>
                      )}
                    </TableCell>
                    <TableCell>
                      <code className="font-mono text-xs">{s.service_url_pattern}</code>
                    </TableCell>
                    <TableCell>
                      {s.released_attributes.length === 0 ? (
                        <span className="text-xs text-on-surface-variant/60">username only</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {s.released_attributes.map((a) => (
                            <Badge key={a} status="pending" label={a} />
                          ))}
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge
                        status={s.enabled ? "operational" : "critical"}
                        label={s.enabled ? "enabled" : "disabled"}
                      />
                    </TableCell>
                    <TableCell>{formatDateTime(s.created_at)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="sm" onClick={() => toggle(s)}>
                          {s.enabled ? "Disable" : "Enable"}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => remove(s)}
                          className="text-error hover:bg-error/10"
                        >
                          Delete
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        </>
      )}
    </>
  );
}

function AddForm({ onCancel, onCreated }: { onCancel: () => void; onCreated: () => void }) {
  const [form, setForm] = useState<CreateCASServiceRequest>({
    name: "",
    service_url_pattern: "",
    description: "",
    released_attributes: [],
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    setBusy(true);
    try {
      await api.createCASService(form);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const valid = form.name.trim() !== "" && form.service_url_pattern.trim() !== "";

  return (
    <Card noHover variant="low" className="mb-6 max-w-2xl">
      <CardHeader>
        <CardTitle>Register a CAS service</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && <Alert variant="error">{error}</Alert>}

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Input
            label="Name"
            required
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="Wiki"
          />
          <div>
            <Input
              label="Service URL pattern"
              required
              className="font-mono"
              value={form.service_url_pattern}
              onChange={(e) => setForm((f) => ({ ...f, service_url_pattern: e.target.value }))}
              placeholder="https://wiki.example.com/"
            />
            <p className="ml-1 mt-1 text-xs text-on-surface-variant">
              Trailing slash is treated as a prefix match.
            </p>
          </div>
        </div>

        {/* Was a comma-separated text field; TagInput makes the list explicit
            and stops "email,, display_name" style entries reaching the API. */}
        <TagInput
          label="Released attributes"
          value={form.released_attributes ?? []}
          onChange={(next) => setForm((f) => ({ ...f, released_attributes: next }))}
          placeholder="email"
        />
        <p className="-mt-2 ml-1 text-xs text-on-surface-variant">
          Leave empty to release the username only.
        </p>

        <Input
          label="Description (optional)"
          value={form.description}
          onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
        />

        <div className="flex justify-end gap-3 pt-2">
          <Button variant="ghost" onClick={onCancel}>Cancel</Button>
          <Button onClick={submit} disabled={busy || !valid}>
            {busy ? "Registering…" : "Register"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
export default CASServices
