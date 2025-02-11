import { useMemo } from 'react';

import { BonsaiHelpers } from '@/bonsai/ontology';
import { RouteRequest, SkipClient } from '@skip-go/client';
import { useQuery } from '@tanstack/react-query';
import { parseUnits } from 'viem';

import { DYDX_DEPOSIT_CHAIN } from '@/constants/chains';
import { timeUnits } from '@/constants/time';
import { DYDX_CHAIN_USDC_DENOM, TokenForTransfer } from '@/constants/tokens';

import { useSkipClient } from '@/hooks/transfers/skipClient';
import { useParameterizedSelector } from '@/hooks/useParameterizedSelector';

async function getSkipWithdrawalRoutes(
  skipClient: SkipClient,
  token: TokenForTransfer,
  amount: string
) {
  const routeOptions: RouteRequest = {
    allowMultiTx: true,
    allowSwaps: true,
    sourceAssetDenom: DYDX_CHAIN_USDC_DENOM,
    sourceAssetChainID: DYDX_DEPOSIT_CHAIN,
    destAssetDenom: token.denom,
    destAssetChainID: token.chainId,
    amountIn: parseUnits(amount, token.decimals).toString(),
    smartRelay: true,
    smartSwapOptions: { evmSwaps: true, splitRoutes: true },
  };

  const [slow, fast] = await Promise.all([
    skipClient.route(routeOptions),
    skipClient.route({ ...routeOptions, goFast: true }),
  ]);

  return { slow, fast };
}

export function useWithdrawalRoutes({
  token,
  amount,
}: {
  token?: TokenForTransfer;
  amount: string;
}) {
  const { skipClient } = useSkipClient();
  const rawAmount = amount && token && parseUnits(amount, token.decimals);

  return useQuery({
    queryKey: ['routes', token?.chainId, token?.denom, amount],
    queryFn: () => getSkipWithdrawalRoutes(skipClient, token!, amount),
    enabled: Boolean(token) && Boolean(rawAmount && rawAmount > 0),
    staleTime: 1 * timeUnits.minute,
    refetchOnMount: 'always',
    placeholderData: (prev) => prev,
    retry: false,
  });
}

export function useWithdrawalDeltas({ withdrawAmount }: { withdrawAmount: string }) {
  const withdrawInput = useMemo(
    () => ({
      subaccountNumber: 0,
      withdrawAmount,
    }),
    [withdrawAmount]
  );

  const modifiedParentSubaccount = useParameterizedSelector(
    BonsaiHelpers.forms.withdraw.createSelectParentSubaccountSummary,
    withdrawInput
  );

  return modifiedParentSubaccount;
}
