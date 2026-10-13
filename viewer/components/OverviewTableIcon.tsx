// Glyph of an _OVERVIEW table (sidebar, case search). Matches each view header.
import AccountTreeOutlinedIcon from "@mui/icons-material/AccountTreeOutlined";
import BoltOutlinedIcon from "@mui/icons-material/BoltOutlined";
import CloudDownloadOutlinedIcon from "@mui/icons-material/CloudDownloadOutlined";
import DeleteOutlineOutlinedIcon from "@mui/icons-material/DeleteOutlineOutlined";
import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";
import DesktopWindowsOutlinedIcon from "@mui/icons-material/DesktopWindowsOutlined";
import DeviceHubOutlinedIcon from "@mui/icons-material/DeviceHubOutlined";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import FolderOpenOutlinedIcon from "@mui/icons-material/FolderOpenOutlined";
import ForumOutlinedIcon from "@mui/icons-material/ForumOutlined";
import HistoryOutlinedIcon from "@mui/icons-material/HistoryOutlined";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import LanguageOutlinedIcon from "@mui/icons-material/LanguageOutlined";
import LinkOutlinedIcon from "@mui/icons-material/LinkOutlined";
import MiscellaneousServicesOutlinedIcon from "@mui/icons-material/MiscellaneousServicesOutlined";
import PhotoLibraryOutlinedIcon from "@mui/icons-material/PhotoLibraryOutlined";
import ReportProblemOutlinedIcon from "@mui/icons-material/ReportProblemOutlined";
import RuleOutlinedIcon from "@mui/icons-material/RuleOutlined";
import SecurityOutlinedIcon from "@mui/icons-material/SecurityOutlined";
import ShieldOutlinedIcon from "@mui/icons-material/ShieldOutlined";
import StorageOutlinedIcon from "@mui/icons-material/StorageOutlined";
import TableChartOutlinedIcon from "@mui/icons-material/TableChartOutlined";
import TaskOutlinedIcon from "@mui/icons-material/TaskOutlined";
import TerminalOutlinedIcon from "@mui/icons-material/TerminalOutlined";
import ViewTimelineOutlinedIcon from "@mui/icons-material/ViewTimelineOutlined";

const ICONS: Record<string, React.ElementType> = {
  TargetInfo: InfoOutlinedIcon,
  FileSystemEntries: FolderOpenOutlinedIcon,
  MFT_Records: FolderOpenOutlinedIcon,
  RecycleBin: DeleteOutlineOutlinedIcon,
  RemoteDesktopHistory: DesktopWindowsOutlinedIcon,
  ExecutionHistory: BoltOutlinedIcon,
  Defender: ShieldOutlinedIcon,
  RegistryExplorer: AccountTreeOutlinedIcon,
  RegistryFindings: RuleOutlinedIcon,
  PowerShellHistory: TerminalOutlinedIcon,
  SmbHistory: DnsOutlinedIcon,
  BitsHistory: CloudDownloadOutlinedIcon,
  FirewallHistory: SecurityOutlinedIcon,
  ScheduledTasks: TaskOutlinedIcon,
  ServiceHistory: MiscellaneousServicesOutlinedIcon,
  RdpCache: PhotoLibraryOutlinedIcon,
  BrowserActivity: LanguageOutlinedIcon,
  UsnJournal: HistoryOutlinedIcon,
  WerReports: ReportProblemOutlinedIcon,
  JumpListEntries: DescriptionOutlinedIcon,
  TimelineActivities: ViewTimelineOutlinedIcon,
  PathReferences: LinkOutlinedIcon,
  Metadata: StorageOutlinedIcon,
  AiConversations: ForumOutlinedIcon,
  WmiSubscriptions: DeviceHubOutlinedIcon,
};

export default function OverviewTableIcon({ name, size = 18, color = "var(--text-faint)" }: { name: string; size?: number; color?: string }) {
  const Icon = ICONS[name] ?? TableChartOutlinedIcon;
  return <Icon sx={{ fontSize: size, color, flexShrink: 0 }} />;
}
