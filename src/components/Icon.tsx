import { type ElementType } from 'react';

import styled from 'styled-components';

import {
  AddressConnectorIcon,
  AppleIcon,
  ArrowIcon,
  Bar3Icon,
  BellIcon,
  BellStrokeIcon,
  BoxCloseIcon,
  CalculatorIcon,
  CaretIcon,
  CautionCircleIcon,
  CautionCircleStrokeIcon,
  ChatIcon,
  CheckCircleIcon,
  CheckIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ClockIcon,
  CloseIcon,
  CoinMarketCapIcon,
  CoinsIcon,
  CommentIcon,
  CopyIcon,
  CurrencySignIcon,
  DepositIcon,
  DepthChartIcon,
  DiscordIcon,
  DownloadIcon,
  EarthIcon,
  EtherscanIcon,
  ExportKeysIcon,
  FastForwardIcon,
  FeedbackIcon,
  FileIcon,
  FundingChartIcon,
  GearIcon,
  GiftboxIcon,
  GooglePlayIcon,
  GovernanceIcon,
  HelpCircleIcon,
  HideIcon,
  HistoryIcon,
  LeaderboardIcon,
  LinkOutIcon,
  ListIcon,
  LockIcon,
  MarketsIcon,
  MenuIcon,
  MigrateIcon,
  MintscanIcon,
  MoneyIcon,
  MoonIcon,
  OrderCanceledIcon,
  OrderFilledIcon,
  OrderOpenIcon,
  OrderPartiallyFilledIcon,
  OrderPendingIcon,
  OrderUntriggeredIcon,
  OrderbookIcon,
  OverviewIcon,
  PencilIcon,
  PlayIcon,
  PlusIcon,
  PositionPartialIcon,
  PositionsIcon,
  PriceChartIcon,
  PrivacyIcon,
  QrIcon,
  RewardStarIcon,
  RocketIcon,
  SearchIcon,
  SendIcon,
  ShareIcon,
  ShowIcon,
  SocialXIcon,
  SpeechBubbleIcon,
  StarIcon,
  SunIcon,
  TerminalIcon,
  TogglesMenuIcon,
  TokenIcon,
  TradeIcon,
  TransferIcon,
  TriangleIcon,
  TryAgainIcon,
  WarningIcon,
  WebsiteIcon,
  WhitepaperIcon,
  WithdrawIcon,
} from '@/icons';
import { ChaosLabsIcon } from '@/icons/chaos-labs';
import { LogoShortIcon } from '@/icons/logo-short';

export enum IconName {
  AddressConnector = 'AddressConnector',
  Apple = 'Apple',
  Arrow = 'Arrow',
  Bar3 = 'Bar3',
  Bell = 'Bell',
  BellStroked = 'BellStroked',
  BoxClose = 'BoxClose',
  Calculator = 'Calculator',
  Caret = 'Caret',
  CautionCircle = 'CautionCircle',
  CautionCircleStroked = 'CautionCircleStroked',
  ChaosLabs = 'ChaosLabs',
  Chat = 'Chat',
  Check = 'Check',
  CheckCircle = 'CheckCircle',
  ChevronLeft = 'ChevronLeft',
  ChevronRight = 'ChevronRight',
  Clock = 'Clock',
  Close = 'Close',
  CoinMarketCap = 'CoinMarketCap',
  Coins = 'Coins',
  Comment = 'Comment',
  Copy = 'Copy',
  CurrencySign = 'CurrencySign',
  Deposit = 'Deposit',
  DepthChart = 'DepthChart',
  Discord = 'Discord',
  Download = 'Download',
  Earth = 'Earth',
  Etherscan = 'Etherscan',
  ExportKeys = 'ExportKeys',
  FastForward = 'FastForward',
  Feedback = 'Feedback',
  File = 'File',
  FundingChart = 'FundingChart',
  Gear = 'Gear',
  Giftbox = 'Giftbox',
  GooglePlay = 'GooglePlay',
  Governance = 'Governance',
  HelpCircle = 'HelpCircle',
  Hide = 'Hide',
  History = 'History',
  Leaderboard = 'Leaderboard',
  LinkOut = 'LinkOut',
  List = 'List',
  Lock = 'Lock',
  LogoShort = 'LogoShort',
  Markets = 'Markets',
  Menu = 'Menu',
  Migrate = 'Migrate',
  Mintscan = 'Mintscan',
  Money = 'Money',
  Moon = 'Moon',
  Onboarding = 'Onboarding',
  Orderbook = 'OrderbookIcon',
  OrderCanceled = 'OrderCanceled',
  OrderFilled = 'OrderFilled',
  OrderOpen = 'OrderOpen',
  OrderPartiallyFilled = 'OrderPartiallyFilled',
  OrderPending = 'OrderPending',
  OrderUntriggered = 'OrderUntriggered',
  Overview = 'Overview',
  Pencil = 'Pencil',
  Play = 'Play',
  Plus = 'Plus',
  PositionPartial = 'PositionPartial',
  Positions = 'Positions',
  PriceChart = 'PriceChart',
  Privacy = 'Privacy',
  Qr = 'Qr',
  RewardStar = 'RewardStar',
  Rocket = 'Rocket',
  Search = 'Search',
  Send = 'Send',
  Share = 'Share',
  Show = 'Show',
  SpeechBubble = 'SpeechBubble',
  Star = 'Star',
  Sun = 'Sun',
  Terminal = 'Terminal',
  TogglesMenu = 'TogglesMenu',
  Token = 'Token',
  Trade = 'Trade',
  Transfer = 'Transfer',
  Triangle = 'Triangle',
  TryAgain = 'TryAgain',
  Warning = 'Warning',
  Website = 'Website',
  Whitepaper = 'Whitepaper',
  Withdraw = 'Withdraw',
  SocialX = 'SocialX',
}

const icons = {
  [IconName.AddressConnector]: AddressConnectorIcon,
  [IconName.Apple]: AppleIcon,
  [IconName.Arrow]: ArrowIcon,
  [IconName.Bar3]: Bar3Icon,
  [IconName.Bell]: BellIcon,
  [IconName.BellStroked]: BellStrokeIcon,
  [IconName.BoxClose]: BoxCloseIcon,
  [IconName.Calculator]: CalculatorIcon,
  [IconName.Caret]: CaretIcon,
  [IconName.CautionCircle]: CautionCircleIcon,
  [IconName.CautionCircleStroked]: CautionCircleStrokeIcon,
  [IconName.ChaosLabs]: ChaosLabsIcon,
  [IconName.Chat]: ChatIcon,
  [IconName.Check]: CheckIcon,
  [IconName.CheckCircle]: CheckCircleIcon,
  [IconName.ChevronLeft]: ChevronLeftIcon,
  [IconName.ChevronRight]: ChevronRightIcon,
  [IconName.Clock]: ClockIcon,
  [IconName.Close]: CloseIcon,
  [IconName.CoinMarketCap]: CoinMarketCapIcon,
  [IconName.Coins]: CoinsIcon,
  [IconName.Comment]: CommentIcon,
  [IconName.Copy]: CopyIcon,
  [IconName.CurrencySign]: CurrencySignIcon,
  [IconName.Deposit]: DepositIcon,
  [IconName.DepthChart]: DepthChartIcon,
  [IconName.Discord]: DiscordIcon,
  [IconName.Download]: DownloadIcon,
  [IconName.Earth]: EarthIcon,
  [IconName.Etherscan]: EtherscanIcon,
  [IconName.ExportKeys]: ExportKeysIcon,
  [IconName.FastForward]: FastForwardIcon,
  [IconName.Feedback]: FeedbackIcon,
  [IconName.File]: FileIcon,
  [IconName.FundingChart]: FundingChartIcon,
  [IconName.Gear]: GearIcon,
  [IconName.Giftbox]: GiftboxIcon,
  [IconName.GooglePlay]: GooglePlayIcon,
  [IconName.Governance]: GovernanceIcon,
  [IconName.HelpCircle]: HelpCircleIcon,
  [IconName.Hide]: HideIcon,
  [IconName.History]: HistoryIcon,
  [IconName.Leaderboard]: LeaderboardIcon,
  [IconName.List]: ListIcon,
  [IconName.LinkOut]: LinkOutIcon,
  [IconName.Lock]: LockIcon,
  [IconName.LogoShort]: LogoShortIcon,
  [IconName.Markets]: MarketsIcon,
  [IconName.Menu]: MenuIcon,
  [IconName.Migrate]: MigrateIcon,
  [IconName.Mintscan]: MintscanIcon,
  [IconName.Money]: MoneyIcon,
  [IconName.Moon]: MoonIcon,
  [IconName.Orderbook]: OrderbookIcon,
  [IconName.OrderCanceled]: OrderCanceledIcon,
  [IconName.OrderFilled]: OrderFilledIcon,
  [IconName.OrderOpen]: OrderOpenIcon,
  [IconName.OrderPartiallyFilled]: OrderPartiallyFilledIcon,
  [IconName.OrderPending]: OrderPendingIcon,
  [IconName.OrderUntriggered]: OrderUntriggeredIcon,
  [IconName.Overview]: OverviewIcon,
  [IconName.Pencil]: PencilIcon,
  [IconName.Play]: PlayIcon,
  [IconName.Plus]: PlusIcon,
  [IconName.PositionPartial]: PositionPartialIcon,
  [IconName.Positions]: PositionsIcon,
  [IconName.PriceChart]: PriceChartIcon,
  [IconName.Privacy]: PrivacyIcon,
  [IconName.Qr]: QrIcon,
  [IconName.RewardStar]: RewardStarIcon,
  [IconName.Rocket]: RocketIcon,
  [IconName.Search]: SearchIcon,
  [IconName.Send]: SendIcon,
  [IconName.Share]: ShareIcon,
  [IconName.Show]: ShowIcon,
  [IconName.SpeechBubble]: SpeechBubbleIcon,
  [IconName.Star]: StarIcon,
  [IconName.Sun]: SunIcon,
  [IconName.Terminal]: TerminalIcon,
  [IconName.TogglesMenu]: TogglesMenuIcon,
  [IconName.Token]: TokenIcon,
  [IconName.Trade]: TradeIcon,
  [IconName.Transfer]: TransferIcon,
  [IconName.Triangle]: TriangleIcon,
  [IconName.TryAgain]: TryAgainIcon,
  [IconName.Warning]: WarningIcon,
  [IconName.Website]: WebsiteIcon,
  [IconName.Whitepaper]: WhitepaperIcon,
  [IconName.Withdraw]: WithdrawIcon,
  [IconName.SocialX]: SocialXIcon,
} as Record<IconName, ElementType>;

type ElementProps = {
  iconName?: IconName;
  iconComponent?: ElementType;
};

type StyleProps = {
  className?: string;
};

export const Icon = styled(
  ({
    iconName,
    iconComponent: Component = iconName && icons[iconName],
    className,
    size,
    ...props
  }: ElementProps & StyleProps & { size?: string }) =>
    Component ? <Component className={className} {...props} /> : null
)`
  width: ${({ size }) => size ?? '1em'};
  height: ${({ size }) => size ?? '1em'};
`;
