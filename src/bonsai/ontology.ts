import { HeightResponse } from '@dydxprotocol/v4-client-js';
import BigNumber from 'bignumber.js';

import { GroupingMultiplier } from '@/constants/orderbook';
import { IndexerWsTradesUpdateObject } from '@/types/indexer/indexerManual';

import { type RootState } from '@/state/_store';
import { getCurrentMarketId } from '@/state/currentMarketSelectors';

import { UsdcDepositArgs, UsdcWithdrawArgs } from './calculators/accountActions';
import { HistoricalFundingObject } from './calculators/funding';
import { Loadable, LoadableStatus } from './lib/loadable';
import { useCurrentMarketHistoricalFunding } from './rest/funding';
import {
  getCurrentMarketAccountFills,
  selectAccountFills,
  selectAccountFillsLoading,
  selectAccountOrdersLoading,
  selectAccountTransfers,
  selectAccountTransfersLoading,
  selectCurrentMarketOpenOrders,
  selectCurrentMarketOrderHistory,
  selectOpenOrders,
  selectOrderHistory,
  selectParentSubaccountOpenPositions,
  selectParentSubaccountOpenPositionsLoading,
  selectParentSubaccountSummary,
  selectParentSubaccountSummaryLoading,
  selectUnopenedIsolatedPositions,
} from './selectors/account';
import {
  createSelectParentSubaccountSummaryDeposit,
  createSelectParentSubaccountSummaryWithdrawal,
} from './selectors/accountActions';
import {
  selectApiState,
  selectLatestIndexerHeight,
  selectLatestValidatorHeight,
} from './selectors/apiStatus';
import {
  createSelectAssetInfo,
  createSelectAssetLogo,
  selectAllAssetsInfo,
  selectAllAssetsInfoLoading,
} from './selectors/assets';
import { selectAccountBalances } from './selectors/balances';
import {
  selectRawIndexerHeightDataLoading,
  selectRawValidatorHeightDataLoading,
} from './selectors/base';
import { selectEquityTiers, selectFeeTiers } from './selectors/configs';
import { selectCurrentMarketOrderbookLoading } from './selectors/markets';
import {
  createSelectCurrentMarketOrderbook,
  selectCurrentMarketDepthChart,
  selectCurrentMarketMidPrice,
} from './selectors/orderbook';
import {
  createSelectMarketSummaryById,
  selectAllMarketSummaries,
  selectAllMarketSummariesLoading,
  selectCurrentMarketAssetId,
  selectCurrentMarketAssetLogoUrl,
  selectCurrentMarketAssetName,
  selectCurrentMarketInfo,
  selectCurrentMarketInfoStable,
  StablePerpetualMarketSummary,
} from './selectors/summary';
import { selectUserStats } from './selectors/userStats';
import { DepthChartData, OrderbookProcessedData } from './types/orderbookTypes';
import {
  AccountBalances,
  AllAssetData,
  ApiState,
  AssetData,
  EquityTiersSummary,
  FeeTierSummary,
  GroupedSubaccountSummary,
  PendingIsolatedPosition,
  PerpetualMarketSummaries,
  PerpetualMarketSummary,
  SubaccountFill,
  SubaccountOrder,
  SubaccountPosition,
  SubaccountTransfer,
  UserStats,
} from './types/summaryTypes';
import { useCurrentMarketTradesValue } from './websocket/trades';

type BasicSelector<Result> = (state: RootState) => Result;
type ParameterizedSelector<Result, Args extends any[]> = () => (
  state: RootState,
  ...args: Args
) => Result;

// all data should be accessed via selectors in this file
// no files outside bonsai should access anything within bonsai except this file
interface BonsaiCoreShape {
  account: {
    parentSubaccountSummary: {
      data: BasicSelector<GroupedSubaccountSummary | undefined>;
      loading: BasicSelector<LoadableStatus>;
    };
    parentSubaccountPositions: {
      data: BasicSelector<SubaccountPosition[] | undefined>;
      loading: BasicSelector<LoadableStatus>;
    };
    openOrders: {
      data: BasicSelector<SubaccountOrder[]>;
      loading: BasicSelector<LoadableStatus>;
    };
    orderHistory: {
      data: BasicSelector<SubaccountOrder[]>;
      loading: BasicSelector<LoadableStatus>;
    };
    fills: {
      data: BasicSelector<SubaccountFill[]>;
      loading: BasicSelector<LoadableStatus>;
    };
    transfers: {
      data: BasicSelector<SubaccountTransfer[]>;
      loading: BasicSelector<LoadableStatus>;
    };
    stats: {
      data: BasicSelector<UserStats>;
    };
    balances: {
      data: BasicSelector<AccountBalances>;
    };
  };
  markets: {
    currentMarketId: BasicSelector<string | undefined>;
    markets: {
      data: BasicSelector<PerpetualMarketSummaries | undefined>;
      loading: BasicSelector<LoadableStatus>;
    };
    assets: {
      data: BasicSelector<AllAssetData | undefined>;
      loading: BasicSelector<LoadableStatus>;
    };
  };
  network: {
    indexerHeight: {
      data: BasicSelector<HeightResponse | undefined>;
      loading: BasicSelector<LoadableStatus>;
    };
    validatorHeight: {
      data: BasicSelector<HeightResponse | undefined>;
      loading: BasicSelector<LoadableStatus>;
    };
    apiState: BasicSelector<ApiState | undefined>;
  };
  configs: {
    feeTiers: BasicSelector<FeeTierSummary[] | undefined>;
    equityTiers: BasicSelector<EquityTiersSummary | undefined>;
  };
}

export const BonsaiCore: BonsaiCoreShape = {
  account: {
    parentSubaccountSummary: {
      data: selectParentSubaccountSummary,
      loading: selectParentSubaccountSummaryLoading,
    },
    parentSubaccountPositions: {
      data: selectParentSubaccountOpenPositions,
      loading: selectParentSubaccountOpenPositionsLoading,
    },
    openOrders: {
      data: selectOpenOrders,
      loading: selectAccountOrdersLoading,
    },
    orderHistory: {
      data: selectOrderHistory,
      loading: selectAccountOrdersLoading,
    },
    fills: {
      data: selectAccountFills,
      loading: selectAccountFillsLoading,
    },
    transfers: {
      data: selectAccountTransfers,
      loading: selectAccountTransfersLoading,
    },
    stats: {
      data: selectUserStats,
    },
    balances: {
      data: selectAccountBalances,
    },
  },
  markets: {
    currentMarketId: getCurrentMarketId,
    markets: {
      data: selectAllMarketSummaries,
      loading: selectAllMarketSummariesLoading,
    },
    assets: {
      data: selectAllAssetsInfo,
      loading: selectAllAssetsInfoLoading,
    },
  },
  network: {
    indexerHeight: {
      data: selectLatestIndexerHeight,
      loading: selectRawIndexerHeightDataLoading,
    },
    validatorHeight: {
      data: selectLatestValidatorHeight,
      loading: selectRawValidatorHeightDataLoading,
    },
    apiState: selectApiState,
  },
  configs: {
    equityTiers: selectEquityTiers,
    feeTiers: selectFeeTiers,
  },
};

interface BonsaiHelpersShape {
  currentMarket: {
    marketInfo: BasicSelector<PerpetualMarketSummary | undefined>;
    // marketInfo but with only the properties that rarely change, for fewer rerenders
    stableMarketInfo: BasicSelector<StablePerpetualMarketSummary | undefined>;

    // direct helpers
    assetId: BasicSelector<string | undefined>;
    assetLogo: BasicSelector<string | undefined>;
    assetName: BasicSelector<string | undefined>;

    account: {
      openOrders: BasicSelector<SubaccountOrder[]>;
      orderHistory: BasicSelector<SubaccountOrder[]>;
      fills: BasicSelector<SubaccountFill[]>;
    };
    orderbook: {
      createSelectGroupedData: ParameterizedSelector<
        OrderbookProcessedData | undefined,
        [GroupingMultiplier | undefined]
      >;
      loading: BasicSelector<LoadableStatus>;
    };
    midPrice: {
      data: BasicSelector<BigNumber | undefined>;
      loading: BasicSelector<LoadableStatus>;
    };
    depthChart: {
      data: BasicSelector<DepthChartData | undefined>;
      loading: BasicSelector<LoadableStatus>;
    };
  };
  assets: {
    createSelectAssetInfo: ParameterizedSelector<AssetData | undefined, [string | undefined]>;
    createSelectAssetLogo: ParameterizedSelector<string | undefined, [string | undefined]>;
  };
  markets: {
    createSelectMarketSummaryById: ParameterizedSelector<
      PerpetualMarketSummary | undefined,
      [string | undefined]
    >;
  };
  forms: {
    deposit: {
      createSelectParentSubaccountSummary: ParameterizedSelector<
        GroupedSubaccountSummary | undefined,
        [UsdcDepositArgs]
      >;
    };
    withdraw: {
      createSelectParentSubaccountSummary: ParameterizedSelector<
        GroupedSubaccountSummary | undefined,
        [UsdcWithdrawArgs]
      >;
    };
  };
  unopenedIsolatedPositions: BasicSelector<PendingIsolatedPosition[] | undefined>;
}

export const BonsaiHelpers: BonsaiHelpersShape = {
  currentMarket: {
    marketInfo: selectCurrentMarketInfo,
    stableMarketInfo: selectCurrentMarketInfoStable,
    assetId: selectCurrentMarketAssetId,
    assetLogo: selectCurrentMarketAssetLogoUrl,
    assetName: selectCurrentMarketAssetName,
    orderbook: {
      createSelectGroupedData: createSelectCurrentMarketOrderbook,
      loading: selectCurrentMarketOrderbookLoading,
    },
    midPrice: {
      data: selectCurrentMarketMidPrice,
      loading: selectCurrentMarketOrderbookLoading,
    },
    depthChart: {
      data: selectCurrentMarketDepthChart,
      loading: selectCurrentMarketOrderbookLoading,
    },
    account: {
      openOrders: selectCurrentMarketOpenOrders,
      orderHistory: selectCurrentMarketOrderHistory,
      fills: getCurrentMarketAccountFills,
    },
  },
  assets: {
    // only use this for launchable assets, otherwise use market info
    createSelectAssetInfo,
    createSelectAssetLogo,
  },
  markets: {
    createSelectMarketSummaryById,
  },
  forms: {
    deposit: {
      createSelectParentSubaccountSummary: createSelectParentSubaccountSummaryDeposit,
    },
    withdraw: {
      createSelectParentSubaccountSummary: createSelectParentSubaccountSummaryWithdrawal,
    },
  },
  unopenedIsolatedPositions: selectUnopenedIsolatedPositions,
};

interface BonsaiHooksShape {
  useCurrentMarketHistoricalFunding: () => Loadable<HistoricalFundingObject[]>;
  useCurrentMarketLiveTrades: () => Loadable<IndexerWsTradesUpdateObject>;
}

export const BonsaiHooks: BonsaiHooksShape = {
  useCurrentMarketHistoricalFunding,
  useCurrentMarketLiveTrades: useCurrentMarketTradesValue,
};
