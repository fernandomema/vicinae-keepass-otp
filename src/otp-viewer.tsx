import { useState, useEffect, useCallback } from "react";
import { readFileSync } from "fs";
import {
  List,
  ActionPanel,
  Action,
  showToast,
  Toast,
  getPreferenceValues,
} from "@vicinae/api";
import { readKdbxOtpEntries, OtpEntry } from "./kdbx";
import { generateTotp, getTimeRemaining } from "./totp";

interface Preferences {
  "kdbx-file": string;
  password?: string;
  "key-file"?: string;
}

interface EntryWithCode extends OtpEntry {
  code: string;
}

export default function OtpViewer() {
  const [entries, setEntries] = useState<EntryWithCode[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [timeLeft, setTimeLeft] = useState(getTimeRemaining());
  const [filter, setFilter] = useState("all");

  const preferences = getPreferenceValues<Preferences>();

  const refreshCodes = useCallback(async (otpEntries: OtpEntry[]) => {
    const withCodes: EntryWithCode[] = [];
    for (const entry of otpEntries) {
      try {
        const code = await generateTotp(entry.config);
        withCodes.push({ ...entry, code });
      } catch {
        // skip entries that fail to generate
      }
    }
    setEntries(withCodes);
  }, []);

  useEffect(() => {
    async function load() {
      try {
        if (!preferences["kdbx-file"]) {
          setError("No database file configured. Set the path in extension preferences.");
          setLoading(false);
          return;
        }

        const fileData = readFileSync(preferences["kdbx-file"]).buffer;

        let keyFileData: ArrayBuffer | undefined;
        if (preferences["key-file"]) {
          keyFileData = readFileSync(preferences["key-file"]).buffer;
        }

        const otpEntries = await readKdbxOtpEntries(
          fileData,
          preferences.password || "",
          keyFileData
        );

        await refreshCodes(otpEntries);
        setLoading(false);
      } catch (e) {
        setError(String(e));
        setLoading(false);
        await showToast({
          title: "Failed to load database",
          message: String(e),
          style: Toast.Style.Failure,
        });
      }
    }
    load();
  }, [preferences["kdbx-file"], preferences.password, preferences["key-file"], refreshCodes]);

  useEffect(() => {
    if (entries.length === 0) return;
    const interval = setInterval(() => {
      setTimeLeft(getTimeRemaining());
      if (getTimeRemaining() === 30) {
        refreshCodes(entries);
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [entries, refreshCodes]);

  const groups = Array.from(new Set(entries.map((e) => e.group))).sort();
  const filtered = filter === "all" ? entries : entries.filter((e) => e.group === filter);

  if (loading) {
    return (
      <List isLoading>
        <List.EmptyView title="Loading KeePass database..." />
      </List>
    );
  }

  if (error) {
    return (
      <List>
        <List.EmptyView
          title="Error"
          description={error}
          actions={
            <ActionPanel>
              <Action title="Retry" onAction={() => { setLoading(true); setError(null); }} />
            </ActionPanel>
          }
        />
      </List>
    );
  }

  if (entries.length === 0) {
    return (
      <List>
        <List.EmptyView
          title="No OTP entries found"
          description="No entries with OTP/TOTP configuration were found in this database."
        />
      </List>
    );
  }

  return (
    <List
      searchBarPlaceholder="Search OTP entries..."
      isLoading={loading}
      searchBarAccessory={
        groups.length > 0 ? (
          <List.Dropdown tooltip="Filter by group" value={filter} onChange={setFilter}>
            <List.Dropdown.Item title="All Groups" value="all" />
            {groups.map((g) => (
              <List.Dropdown.Item key={g} title={g} value={g} />
            ))}
          </List.Dropdown>
        ) : undefined
      }
    >
      {filtered.map((entry) => (
        <List.Item
          key={`${entry.group}-${entry.title}`}
          title={entry.title}
          subtitle={entry.username}
          icon="🔑"
          accessories={[
            { text: entry.code },
            {
              tag: {
                value: `${timeLeft}s`,
                color: timeLeft <= 5 ? "red" : timeLeft <= 10 ? "orange" : "green",
              },
            },
          ]}
          detail={
            <List.Item.Detail
              markdown={`# ${entry.title}\n\n**OTP Code:** \`${entry.code}\`\n\n**Time remaining:** ${timeLeft}s\n\n---\n\n**Group:** ${entry.group}\n\n**Username:** ${entry.username}\n\n**Algorithm:** ${entry.config.algorithm}\n\n**Digits:** ${entry.config.digits}\n\n**Period:** ${entry.config.period}s`}
            />
          }
          actions={
            <ActionPanel>
              <Action.CopyToClipboard title="Copy OTP Code" content={entry.code} concealed />
              <Action.Paste title="Paste OTP Code" content={entry.code} />
              <Action.CopyToClipboard title="Copy Secret Key" content={entry.config.secret} concealed />
              <Action title="Refresh Codes" onAction={() => refreshCodes(entries)} />
            </ActionPanel>
          }
        />
      ))}
    </List>
  );
}
