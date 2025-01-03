import { forwardRef, Key, ReactNode, useEffect, useMemo } from 'react';

import { OrderSide } from '@dydxprotocol/v4-client-js';
import { ColumnSize } from '@react-types/table';
import type { Dispatch } from '@reduxjs/toolkit';
import { shallowEqual } from 'react-redux';
import styled, { css } from 'styled-components';
import tw from 'twin.macro';

import { AbacusMarginMode, Asset, Nullable, SubaccountOrder } from '@/constants/abacus';
import { DialogTypes } from '@/constants/dialogs';
import { STRING_KEYS, type StringGetterFunction } from '@/constants/localization';
import { TOKEN_DECIMALS } from '@/constants/numbers';
import { EMPTY_ARR } from '@/constants/objects';

import { useBreakpoints } from '@/hooks/useBreakpoints';
import { useStringGetter } from '@/hooks/useStringGetter';

import breakpoints from '@/styles/breakpoints';
import { layoutMixins } from '@/styles/layoutMixins';
import { tradeViewMixins } from '@/styles/tradeViewMixins';

import { AssetIcon } from '@/components/AssetIcon';
import { Icon, IconName } from '@/components/Icon';
import { OrderSideTag } from '@/components/OrderSideTag';
import { Output, OutputType } from '@/components/Output';
import { ColumnDef, Table } from '@/components/Table';
import { MarketTableCell } from '@/components/Table/MarketTableCell';
import { TableCell } from '@/components/Table/TableCell';
import { TableColumnHeader } from '@/components/Table/TableColumnHeader';
import { PageSize } from '@/components/Table/TablePaginationRow';
import { Tag, TagSize } from '@/components/Tag';
import { WithTooltip } from '@/components/WithTooltip';
import { MarketTypeFilter, marketTypeMatchesFilter } from '@/pages/trade/types';

import { viewedOrders } from '@/state/account';
import { calculateIsAccountViewOnly } from '@/state/accountCalculators';
import {
  getCurrentMarketOrders,
  getHasUnseenOrderUpdates,
  getSubaccountUnclearedOrders,
} from '@/state/accountSelectors';
import { useAppDispatch, useAppSelector } from '@/state/appTypes';
import { getAssets } from '@/state/assetsSelectors';
import { openDialog } from '@/state/dialogs';
import { getPerpetualMarkets } from '@/state/perpetualsSelectors';

import { mapIfPresent } from '@/lib/do';
import { MustBigNumber } from '@/lib/numbers';
import {
  getHydratedTradingData,
  getOrderStatusInfo,
  isMarketOrderType,
  isOrderStatusClearable,
} from '@/lib/orders';
import { getMarginModeFromSubaccountNumber } from '@/lib/tradeData';
import { orEmptyRecord } from '@/lib/typeUtils';

import { OrderStatusIcon } from '../OrderStatusIcon';
import { CancelOrClearAllOrdersButton } from './OrdersTable/CancelOrClearAllOrdersButton';
import { OrderActionsCell } from './OrdersTable/OrderActionsCell';

export enum OrdersTableColumnKey {
  Market = 'Market',
  Status = 'Status',
  Side = 'Side',
  Amount = 'Amount',
  Filled = 'Filled',
  OrderValue = 'Order-Value',
  Price = 'Price',
  Trigger = 'Trigger',
  GoodTil = 'Good-Til',
  Actions = 'Actions',
  MarginType = 'Margin-Type',

  // TODO: CT-1292 remove deprecated fields
  AmountFill = 'Amount-Fill',

  // Tablet Only
  StatusFill = 'Status-Fill',
  PriceType = 'Price-Type',
}

export type OrderTableRow = {
  asset: Nullable<Asset>;
  stepSizeDecimals: Nullable<number>;
  tickSizeDecimals: Nullable<number>;
  orderSide?: Nullable<OrderSide>;
} & SubaccountOrder;

const getOrdersTableColumnDef = ({
  key,
  currentMarket,
  stringGetter,
  symbol = '',
  isAccountViewOnly,
  width,
}: {
  key: OrdersTableColumnKey;
  currentMarket?: string;
  dispatch: Dispatch;
  isTablet?: boolean;
  stringGetter: StringGetterFunction;
  symbol?: Nullable<string>;
  isAccountViewOnly: boolean;
  width?: ColumnSize;
}): ColumnDef<OrderTableRow> => ({
  width,

  ...(
    {
      [OrdersTableColumnKey.Market]: {
        columnKey: 'marketId',
        getCellValue: (row) => row.marketId,
        label: stringGetter({ key: STRING_KEYS.MARKET }),
        renderCell: ({ asset }) => <MarketTableCell asset={asset ?? undefined} />,
      },
      [OrdersTableColumnKey.Status]: {
        columnKey: 'status',
        getCellValue: (row) => row.status.name,
        label: stringGetter({ key: STRING_KEYS.STATUS }),
        renderCell: ({ status, resources }) => {
          return (
            <TableCell>
              <WithTooltip
                tooltipString={
                  resources.statusStringKey
                    ? stringGetter({ key: resources.statusStringKey })
                    : undefined
                }
                side="right"
                tw="[--tooltip-backgroundColor:--color-layer-5]"
              >
                <OrderStatusIcon status={status.rawValue} />
              </WithTooltip>
              {resources.typeStringKey && stringGetter({ key: resources.typeStringKey })}
            </TableCell>
          );
        },
      },
      [OrdersTableColumnKey.Side]: {
        columnKey: 'side',
        getCellValue: (row) => row.orderSide,
        label: stringGetter({ key: STRING_KEYS.SIDE }),
        renderCell: ({ orderSide }) => (
          <OrderSideTag orderSide={orderSide ?? OrderSide.BUY} size={TagSize.Medium} />
        ),
      },
      [OrdersTableColumnKey.AmountFill]: {
        columnKey: 'size',
        getCellValue: (row) => row.size,
        label: (
          <TableColumnHeader>
            <span>{stringGetter({ key: STRING_KEYS.AMOUNT })}</span>
            <span>{stringGetter({ key: STRING_KEYS.AMOUNT_FILLED })}</span>
          </TableColumnHeader>
        ),
        tag: symbol,
        renderCell: ({ size, totalFilled, stepSizeDecimals }) => (
          <TableCell stacked>
            <Output
              type={OutputType.Asset}
              value={size}
              fractionDigits={stepSizeDecimals ?? TOKEN_DECIMALS}
            />
            <Output
              type={OutputType.Asset}
              value={totalFilled}
              fractionDigits={stepSizeDecimals ?? TOKEN_DECIMALS}
            />
          </TableCell>
        ),
      },
      [OrdersTableColumnKey.Amount]: {
        columnKey: 'amount',
        getCellValue: (row) => row.size,
        label: stringGetter({ key: STRING_KEYS.AMOUNT }),
        tag: symbol,
        renderCell: ({ size, stepSizeDecimals }) => (
          <TableCell>
            <Output
              type={OutputType.Asset}
              value={size}
              fractionDigits={stepSizeDecimals ?? TOKEN_DECIMALS}
            />
          </TableCell>
        ),
      },
      [OrdersTableColumnKey.Filled]: {
        columnKey: 'filled',
        getCellValue: (row) => row.totalFilled,
        label: stringGetter({ key: STRING_KEYS.AMOUNT_FILLED }),
        tag: symbol,
        renderCell: ({ totalFilled, stepSizeDecimals }) => (
          <TableCell>
            <Output
              type={OutputType.Asset}
              value={totalFilled}
              fractionDigits={stepSizeDecimals ?? TOKEN_DECIMALS}
            />
          </TableCell>
        ),
      },
      [OrdersTableColumnKey.OrderValue]: {
        columnKey: 'orderValue',
        getCellValue: (row) =>
          MustBigNumber(row.size)
            .abs()
            .multipliedBy(row.triggerPrice ?? row.price)
            .toNumber(),
        label: stringGetter({ key: STRING_KEYS.ORDER_VALUE }),
        renderCell: ({ size, price, triggerPrice }) => (
          <TableCell>
            <Output
              type={OutputType.Fiat}
              value={MustBigNumber(size)
                .abs()
                .multipliedBy(triggerPrice ?? price)}
            />
          </TableCell>
        ),
      },
      [OrdersTableColumnKey.Price]: {
        columnKey: 'price',
        getCellValue: (row) => row.price,
        label: stringGetter({ key: STRING_KEYS.PRICE }),
        renderCell: ({ type, price, tickSizeDecimals }) =>
          isMarketOrderType(type) ? (
            stringGetter({ key: STRING_KEYS.MARKET_PRICE_SHORT })
          ) : (
            <Output
              withSubscript
              type={OutputType.Fiat}
              value={price}
              fractionDigits={tickSizeDecimals}
            />
          ),
      },
      [OrdersTableColumnKey.Trigger]: {
        columnKey: 'triggerPrice',
        getCellValue: (row) => row.triggerPrice ?? -1,
        label: stringGetter({ key: STRING_KEYS.TRIGGER_PRICE_SHORT }),
        renderCell: ({ triggerPrice, trailingPercent, tickSizeDecimals }) => (
          <TableCell stacked>
            <Output
              withSubscript
              type={OutputType.Fiat}
              value={triggerPrice}
              fractionDigits={tickSizeDecimals}
            />
            {trailingPercent && (
              <span>
                <Output
                  type={OutputType.Percent}
                  value={MustBigNumber(trailingPercent).abs().div(100)}
                />{' '}
                {stringGetter({ key: STRING_KEYS.TRAIL })}
              </span>
            )}
          </TableCell>
        ),
      },
      [OrdersTableColumnKey.GoodTil]: {
        columnKey: 'expiresAtMilliseconds',
        getCellValue: (row) => row.expiresAtMilliseconds ?? Infinity,
        label: stringGetter({ key: STRING_KEYS.GOOD_TIL }),
        renderCell: ({ expiresAtMilliseconds }) => {
          if (!expiresAtMilliseconds) return <Output type={OutputType.Text} />;

          return (
            <Output
              type={OutputType.RelativeTime}
              value={expiresAtMilliseconds}
              relativeTimeOptions={{ format: 'singleCharacter' }}
            />
          );
        },
      },
      [OrdersTableColumnKey.Actions]: {
        columnKey: 'cancelOrClear',
        label: <CancelOrClearAllOrdersButton marketId={currentMarket} />,
        isActionable: true,
        allowsSorting: false,
        renderCell: ({ id, status, orderFlags }) => (
          <OrderActionsCell
            orderId={id}
            status={status}
            orderFlags={orderFlags}
            isDisabled={isAccountViewOnly}
          />
        ),
      },
      [OrdersTableColumnKey.StatusFill]: {
        columnKey: 'statusFill',
        getCellValue: (row) => row.status.name,
        label: (
          <TableColumnHeader>
            <span>{stringGetter({ key: STRING_KEYS.STATUS })}</span>
            <span>
              {stringGetter({
                key: STRING_KEYS.FILL,
              })}
            </span>
          </TableColumnHeader>
        ),
        renderCell: ({ asset, createdAtMilliseconds, size, status, totalFilled, resources }) => {
          const { statusIconColor } = getOrderStatusInfo({ status: status.rawValue });

          return (
            <TableCell
              stacked
              slotLeft={
                <>
                  <Output
                    type={OutputType.RelativeTime}
                    relativeTimeOptions={{ format: 'singleCharacter' }}
                    value={createdAtMilliseconds}
                    tw="text-color-text-0"
                  />
                  <$AssetIconWithStatus>
                    <$AssetIcon logoUrl={asset?.resources?.imageUrl} symbol={asset?.id} />
                    <$StatusDot color={statusIconColor} />
                  </$AssetIconWithStatus>
                </>
              }
            >
              <span>
                {resources.statusStringKey && stringGetter({ key: resources.statusStringKey })}
              </span>
              <$InlineRow>
                <Output
                  type={OutputType.Asset}
                  value={totalFilled}
                  fractionDigits={TOKEN_DECIMALS}
                />
                /
                <Output
                  type={OutputType.Asset}
                  value={size}
                  fractionDigits={TOKEN_DECIMALS}
                  tag={asset?.id}
                />
              </$InlineRow>
            </TableCell>
          );
        },
      },
      [OrdersTableColumnKey.PriceType]: {
        columnKey: 'priceType',
        label: (
          <TableColumnHeader>
            <span>{stringGetter({ key: STRING_KEYS.PRICE })}</span>
            <span>{stringGetter({ key: STRING_KEYS.TYPE })}</span>
          </TableColumnHeader>
        ),
        getCellValue: (row) => row.price,
        renderCell: ({ price, orderSide, tickSizeDecimals, resources }) => (
          <TableCell stacked>
            <$InlineRow>
              <$Side side={orderSide}>
                {resources.sideStringKey ? stringGetter({ key: resources.sideStringKey }) : null}
              </$Side>
              <span tw="text-color-text-0">@</span>
              <Output
                withSubscript
                type={OutputType.Fiat}
                value={price}
                fractionDigits={tickSizeDecimals}
              />
            </$InlineRow>
            <span>
              {resources.typeStringKey ? stringGetter({ key: resources.typeStringKey }) : null}
            </span>
          </TableCell>
        ),
      },
      [OrdersTableColumnKey.MarginType]: {
        columnKey: 'marginType',
        label: stringGetter({ key: STRING_KEYS.MARGIN_MODE }),
        getCellValue: (row) => getMarginModeFromSubaccountNumber(row.subaccountNumber).name,
        renderCell(row: OrderTableRow): ReactNode {
          const marginMode = getMarginModeFromSubaccountNumber(row.subaccountNumber);

          const marginModeLabel =
            marginMode === AbacusMarginMode.Cross
              ? stringGetter({ key: STRING_KEYS.CROSS })
              : stringGetter({ key: STRING_KEYS.ISOLATED });
          return <Tag> {marginModeLabel} </Tag>;
        },
      },
    } satisfies Record<OrdersTableColumnKey, ColumnDef<OrderTableRow>>
  )[key],
});

type ElementProps = {
  columnKeys: OrdersTableColumnKey[];
  columnWidths?: Partial<Record<OrdersTableColumnKey, ColumnSize>>;
  currentMarket?: string;
  marketTypeFilter?: MarketTypeFilter;
  initialPageSize?: PageSize;
};

type StyleProps = {
  withOuterBorder?: boolean;
};

export const OrdersTable = forwardRef(
  (
    {
      columnKeys = [],
      columnWidths,
      currentMarket,
      marketTypeFilter,
      initialPageSize,
      withOuterBorder,
    }: ElementProps & StyleProps,
    _ref
  ) => {
    const stringGetter = useStringGetter();
    const dispatch = useAppDispatch();
    const { isTablet } = useBreakpoints();

    const isAccountViewOnly = useAppSelector(calculateIsAccountViewOnly);
    const marketOrders = useAppSelector(getCurrentMarketOrders, shallowEqual) ?? EMPTY_ARR;
    const allOrders = useAppSelector(getSubaccountUnclearedOrders, shallowEqual) ?? EMPTY_ARR;

    const orders = useMemo(
      () =>
        (currentMarket ? marketOrders : allOrders).filter((order) => {
          const orderType = getMarginModeFromSubaccountNumber(order.subaccountNumber).name;
          return marketTypeMatchesFilter(orderType, marketTypeFilter);
        }),
      [allOrders, currentMarket, marketOrders, marketTypeFilter]
    );

    const allPerpetualMarkets = orEmptyRecord(useAppSelector(getPerpetualMarkets, shallowEqual));
    const allAssets = orEmptyRecord(useAppSelector(getAssets, shallowEqual));

    const hasUnseenOrderUpdates = useAppSelector(getHasUnseenOrderUpdates);

    useEffect(() => {
      if (hasUnseenOrderUpdates) dispatch(viewedOrders());
    }, [hasUnseenOrderUpdates]);

    const symbol = mapIfPresent(currentMarket, (market) =>
      mapIfPresent(allPerpetualMarkets[market]?.assetId, (assetId) => allAssets[assetId]?.id)
    );

    const ordersData = useMemo(
      () =>
        orders.map(
          (order: SubaccountOrder): OrderTableRow =>
            getHydratedTradingData({
              data: order,
              assets: allAssets,
              perpetualMarkets: allPerpetualMarkets,
            })
        ),
      [orders, allPerpetualMarkets, allAssets]
    );

    return (
      <$Table
        key={currentMarket ?? 'all-orders'}
        label="Orders"
        data={ordersData}
        getRowKey={(row: OrderTableRow) => row.id}
        getRowAttributes={(row: OrderTableRow) => ({
          'data-clearable': isOrderStatusClearable(row.status),
        })}
        onRowAction={(key: Key) =>
          dispatch(openDialog(DialogTypes.OrderDetails({ orderId: `${key}` })))
        }
        columns={columnKeys.map((key: OrdersTableColumnKey) =>
          getOrdersTableColumnDef({
            key,
            currentMarket,
            dispatch,
            isTablet,
            stringGetter,
            symbol,
            isAccountViewOnly,
            width: columnWidths?.[key],
          })
        )}
        slotEmpty={
          <>
            <Icon iconName={IconName.OrderPending} tw="text-[3em]" />
            <h4>{stringGetter({ key: STRING_KEYS.ORDERS_EMPTY_STATE })}</h4>
          </>
        }
        initialPageSize={initialPageSize}
        withOuterBorder={withOuterBorder}
        withInnerBorders
        withScrollSnapColumns
        withScrollSnapRows
        withFocusStickyRows
      />
    );
  }
);
const $Table = styled(Table)`
  ${tradeViewMixins.horizontalTable}

  tbody tr {
    &[data-clearable='true'] {
      opacity: 0.5;
    }
  }
` as typeof Table;

const $InlineRow = tw.div`inlineRow`;

const $AssetIcon = styled(AssetIcon)`
  font-size: 2rem;

  @media ${breakpoints.tablet} {
    font-size: 2.25rem;
  }
`;
const $Side = styled.span<{ side?: OrderSide | null }>`
  ${({ side }) =>
    side &&
    {
      [OrderSide.BUY]: css`
        color: var(--color-positive);
      `,
      [OrderSide.SELL]: css`
        color: var(--color-negative);
      `,
    }[side]};
`;
const $AssetIconWithStatus = styled.div`
  ${layoutMixins.stack}

  ${$AssetIcon} {
    margin: 0.125rem;
  }
`;

const $StatusDot = styled.div<{ color: string }>`
  place-self: start end;
  width: 0.875rem;
  height: 0.875rem;
  border-radius: 50%;
  border: 2px solid var(--tableRow-currentBackgroundColor);

  background-color: ${({ color }) => color};
`;
