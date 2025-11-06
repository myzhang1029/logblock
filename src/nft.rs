use std::{collections::HashSet, net::IpAddr};

/// nftables driver module
///
/// We create one `inet` table with a `logblock` input chain
/// and a `logblock` set to hold blocked IPs.
use nftables::{batch::Batch, expr, helper, schema, stmt, types};

const TABLE_NAME: &str = "logblock";
const CHAIN_NAME: &str = "input";
const SET4_NAME: &str = "logblock_v4";
const SET6_NAME: &str = "logblock_v6";

pub fn init_tables() -> anyhow::Result<()> {
    // Clean up any existing tables first
    uninit_tables().ok();
    let mut batch = Batch::new();
    // Table to hold our stuff
    batch.add(schema::NfListObject::Table(schema::Table {
        family: types::NfFamily::INet,
        name: TABLE_NAME.into(),
        ..Default::default()
    }));
    // Input chain
    batch.add(schema::NfListObject::Chain(schema::Chain {
        family: types::NfFamily::INet,
        table: TABLE_NAME.into(),
        name: CHAIN_NAME.into(),
        _type: Some(types::NfChainType::Filter),
        hook: Some(types::NfHook::Input),
        prio: Some(0),
        policy: Some(types::NfChainPolicy::Accept),
        ..Default::default()
    }));
    // IPv4 and IPv6 sets for blocked IPs
    batch.add(schema::NfListObject::Set(Box::new(schema::Set {
        family: types::NfFamily::INet,
        table: TABLE_NAME.into(),
        name: SET4_NAME.into(),
        set_type: schema::SetTypeValue::Single(schema::SetType::Ipv4Addr),
        flags: Some(HashSet::from([schema::SetFlag::Interval])),
        counter: Some(true),
        auto_merge: Some(true),
        ..Default::default()
    })));
    batch.add(schema::NfListObject::Set(Box::new(schema::Set {
        family: types::NfFamily::INet,
        table: TABLE_NAME.into(),
        name: SET6_NAME.into(),
        set_type: schema::SetTypeValue::Single(schema::SetType::Ipv6Addr),
        flags: Some(HashSet::from([schema::SetFlag::Interval])),
        counter: Some(true),
        auto_merge: Some(true),
        ..Default::default()
    })));
    // Input chain rule to drop packets from blocked IPs
    batch.add(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::INet,
        table: TABLE_NAME.into(),
        chain: CHAIN_NAME.into(),
        expr: vec![
            stmt::Statement::Match(stmt::Match {
                left: expr::Expression::Named(expr::NamedExpression::Payload(
                    expr::Payload::PayloadField(expr::PayloadField {
                        protocol: "ip".into(),
                        field: "saddr".into(),
                    }),
                )),
                right: expr::Expression::String(format!("@{SET4_NAME}").into()),
                op: stmt::Operator::IN,
            }),
            stmt::Statement::Drop(Some(stmt::Drop {})),
        ]
        .into(),
        ..Default::default()
    }));
    batch.add(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::INet,
        table: TABLE_NAME.into(),
        chain: CHAIN_NAME.into(),
        expr: vec![
            stmt::Statement::Match(stmt::Match {
                left: expr::Expression::Named(expr::NamedExpression::Payload(
                    expr::Payload::PayloadField(expr::PayloadField {
                        protocol: "ip6".into(),
                        field: "saddr".into(),
                    }),
                )),
                right: expr::Expression::String(format!("@{SET6_NAME}").into()),
                op: stmt::Operator::IN,
            }),
            stmt::Statement::Drop(Some(stmt::Drop {})),
        ]
        .into(),
        ..Default::default()
    }));
    log::debug!("nftables init ruleset: {batch:?}");
    let ruleset = batch.to_nftables();
    //helper::apply_ruleset_with_args::<'_, str, &str, _>(&ruleset, Some("/usr/bin/log"), &[])?;
    helper::apply_ruleset(&ruleset)?;
    Ok(())
}

pub fn uninit_tables() -> anyhow::Result<()> {
    let mut batch = Batch::new();
    batch.delete(schema::NfListObject::Table(schema::Table {
        family: types::NfFamily::INet,
        name: TABLE_NAME.into(),
        ..Default::default()
    }));
    let ruleset = batch.to_nftables();
    helper::apply_ruleset(&ruleset)?;
    Ok(())
}

pub fn block_ip(ip: IpAddr) -> anyhow::Result<()> {
    let mut batch = Batch::new();
    match ip {
        IpAddr::V4(ipv4) => {
            batch.add(schema::NfListObject::Element(schema::Element {
                family: types::NfFamily::INet,
                table: TABLE_NAME.into(),
                name: SET4_NAME.into(),
                elem: vec![expr::Expression::String(ipv4.to_string().into())].into(),
            }));
        }
        IpAddr::V6(ipv6) => {
            batch.add(schema::NfListObject::Element(schema::Element {
                family: types::NfFamily::INet,
                table: TABLE_NAME.into(),
                name: SET6_NAME.into(),
                elem: vec![expr::Expression::String(ipv6.to_string().into())].into(),
            }));
        }
    }
    let ruleset = batch.to_nftables();
    helper::apply_ruleset(&ruleset)?;
    Ok(())
}

pub fn unblock_ip(ip: IpAddr) -> anyhow::Result<()> {
    let mut batch = Batch::new();
    match ip {
        IpAddr::V4(ipv4) => {
            batch.delete(schema::NfListObject::Element(schema::Element {
                family: types::NfFamily::INet,
                table: TABLE_NAME.into(),
                name: SET4_NAME.into(),
                elem: vec![expr::Expression::String(ipv4.to_string().into())].into(),
            }));
        }
        IpAddr::V6(ipv6) => {
            batch.delete(schema::NfListObject::Element(schema::Element {
                family: types::NfFamily::INet,
                table: TABLE_NAME.into(),
                name: SET6_NAME.into(),
                elem: vec![expr::Expression::String(ipv6.to_string().into())].into(),
            }));
        }
    }
    let ruleset = batch.to_nftables();
    helper::apply_ruleset(&ruleset)?;
    Ok(())
}
