from __future__ import annotations

from datetime import datetime
from urllib.parse import quote

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import case, cast, func, Float, Integer, or_, String, select, text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.alert import Alert
from app.models.detection import Detection
from app.models.network_event import NetworkEvent
from app.models.user import User
from app.schemas.network import (
    NetworkEventDetailResponse,
    NetworkEventListResponse,
    NetworkEventResponse,
    NetworkIPDetailResponse,
    NetworkPortListResponse,
    NetworkPortResponse,
    NetworkProtocolListResponse,
    NetworkProtocolResponse,
    NetworkSummaryResponse,
    NetworkTimelinePoint,
    NetworkTimelineResponse,
    NetworkTopTalkerListResponse,
    NetworkTopTalkerResponse,
)
from app.services.audit import AuditService
from app.services.audit_enums import AuditAction, AuditResult

router = APIRouter(prefix="/network", tags=["network"])


def _get_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _apply_event_filters(
    stmt,
    source_ip: str | None,
    destination_ip: str | None,
    source_port: int | None,
    destination_port: int | None,
    protocol: str | None,
    search: str | None,
    from_timestamp: str | None,
    to_timestamp: str | None,
    analysis_run_id: str | None,
    detection_id: str | None,
    alert_id: str | None,
):
    if source_ip:
        stmt = stmt.where(NetworkEvent.source_ip.ilike(f"%{source_ip}%"))
    if destination_ip:
        stmt = stmt.where(NetworkEvent.destination_ip.ilike(f"%{destination_ip}%"))
    if source_port is not None:
        stmt = stmt.where(NetworkEvent.source_port == source_port)
    if destination_port is not None:
        stmt = stmt.where(NetworkEvent.destination_port == destination_port)
    if protocol:
        stmt = stmt.where(NetworkEvent.protocol.ilike(f"%{protocol}%"))
    if analysis_run_id:
        stmt = stmt.where(NetworkEvent.analysis_run_id == analysis_run_id)
    if detection_id:
        stmt = stmt.where(NetworkEvent.detection_id == detection_id)
    if alert_id:
        stmt = stmt.where(NetworkEvent.alert_id == alert_id)
    if from_timestamp:
        dt = _parse_iso(from_timestamp)
        if dt:
            stmt = stmt.where(NetworkEvent.timestamp >= dt)
    if to_timestamp:
        dt = _parse_iso(to_timestamp)
        if dt:
            stmt = stmt.where(NetworkEvent.timestamp <= dt)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(
            or_(
                NetworkEvent.source_ip.ilike(pattern),
                NetworkEvent.destination_ip.ilike(pattern),
                NetworkEvent.protocol.ilike(pattern),
                NetworkEvent.connection_id.ilike(pattern),
                NetworkEvent.syscall_name.ilike(pattern),
                NetworkEvent.description.ilike(pattern),
            )
        )
    return stmt


def _parse_iso(raw: str) -> datetime | None:
    try:
        s = raw.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


@router.get("/events", response_model=NetworkEventListResponse)
def list_network_events(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    search: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    protocol: str | None = None,
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    analysis_run_id: str | None = None,
    detection_id: str | None = None,
    alert_id: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(NetworkEvent)
    stmt = _apply_event_filters(
        stmt, source_ip, destination_ip, source_port, destination_port,
        protocol, search, from_timestamp, to_timestamp,
        analysis_run_id, detection_id, alert_id,
    )
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = db.scalar(count_stmt) or 0
    total_pages = max((total + page_size - 1) // page_size, 1)

    items = db.scalars(
        stmt.order_by(NetworkEvent.timestamp.desc().nullslast(), NetworkEvent.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()

    audit = AuditService(db)
    audit.record(
        action=AuditAction.NETWORK_DATA_VIEWED,
        result=AuditResult.SUCCESS,
        actor_user_id=current_user.id,
        actor_email=current_user.email,
        resource_type="NETWORK_EVENT",
        ip_address=_get_ip(request),
        metadata={"page": page, "total": total},
    )
    db.commit()

    return NetworkEventListResponse(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


@router.get("/summary", response_model=NetworkSummaryResponse)
def get_network_summary(
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    analysis_run_id: str | None = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    base = select(NetworkEvent)
    if from_timestamp:
        dt = _parse_iso(from_timestamp)
        if dt:
            base = base.where(NetworkEvent.timestamp >= dt)
    if to_timestamp:
        dt = _parse_iso(to_timestamp)
        if dt:
            base = base.where(NetworkEvent.timestamp <= dt)
    if analysis_run_id:
        base = base.where(NetworkEvent.analysis_run_id == analysis_run_id)

    sub = base.subquery()
    total = db.scalar(select(func.count()).select_from(sub)) or 0
    unique_src = db.scalar(
        select(func.count(func.distinct(sub.c.source_ip))).select_from(sub).where(sub.c.source_ip.isnot(None))
    ) or 0
    unique_dst = db.scalar(
        select(func.count(func.distinct(sub.c.destination_ip))).select_from(sub).where(sub.c.destination_ip.isnot(None))
    ) or 0

    port_q = select(
        func.count(func.distinct(
            case(
                (sub.c.source_port.isnot(None), sub.c.source_port),
                else_=sub.c.destination_port,
            )
        )).label("cnt")
    ).select_from(sub).where(or_(sub.c.source_port.isnot(None), sub.c.destination_port.isnot(None)))
    unique_ports = db.scalar(port_q) or 0

    protocols = db.scalars(
        select(func.distinct(sub.c.protocol)).select_from(sub).where(sub.c.protocol.isnot(None))
    ).all()

    return NetworkSummaryResponse(
        total_events=total,
        unique_source_ips=unique_src,
        unique_destination_ips=unique_dst,
        unique_ports=unique_ports,
        protocols_observed=sorted(protocols),
    )


@router.get("/ips/{ip_address}", response_model=NetworkIPDetailResponse)
def get_ip_detail(
    ip_address: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ip_events = select(NetworkEvent).where(
        or_(NetworkEvent.source_ip == ip_address, NetworkEvent.destination_ip == ip_address)
    )

    first_seen = db.scalar(select(func.min(NetworkEvent.timestamp)).where(
        or_(NetworkEvent.source_ip == ip_address, NetworkEvent.destination_ip == ip_address)
    ))
    last_seen = db.scalar(select(func.max(NetworkEvent.timestamp)).where(
        or_(NetworkEvent.source_ip == ip_address, NetworkEvent.destination_ip == ip_address)
    ))
    total = db.scalar(select(func.count()).select_from(ip_events.subquery())) or 0

    unique_destinations = db.scalar(
        select(func.count(func.distinct(NetworkEvent.destination_ip)))
        .where(NetworkEvent.source_ip == ip_address)
        .where(NetworkEvent.destination_ip.isnot(None))
    ) or 0

    unique_sources = db.scalar(
        select(func.count(func.distinct(NetworkEvent.source_ip)))
        .where(NetworkEvent.destination_ip == ip_address)
        .where(NetworkEvent.source_ip.isnot(None))
    ) or 0

    all_ports = db.scalars(
        select(func.distinct(
            case(
                (NetworkEvent.source_port.isnot(None), NetworkEvent.source_port),
                else_=NetworkEvent.destination_port,
            )
        )).where(
            or_(NetworkEvent.source_ip == ip_address, NetworkEvent.destination_ip == ip_address)
        ).where(
            or_(NetworkEvent.source_port.isnot(None), NetworkEvent.destination_port.isnot(None))
        )
    ).all()
    unique_ports = len(all_ports)

    protocols = db.scalars(
        select(func.distinct(NetworkEvent.protocol)).where(
            or_(NetworkEvent.source_ip == ip_address, NetworkEvent.destination_ip == ip_address)
        ).where(NetworkEvent.protocol.isnot(None))
    ).all()

    related_det_count = db.scalar(
        select(func.count(func.distinct(NetworkEvent.detection_id))).where(
            or_(NetworkEvent.source_ip == ip_address, NetworkEvent.destination_ip == ip_address)
        ).where(NetworkEvent.detection_id.isnot(None))
    ) or 0

    related_alert_count = db.scalar(
        select(func.count(func.distinct(NetworkEvent.alert_id))).where(
            or_(NetworkEvent.source_ip == ip_address, NetworkEvent.destination_ip == ip_address)
        ).where(NetworkEvent.alert_id.isnot(None))
    ) or 0

    audit = AuditService(db)
    audit.record(
        action=AuditAction.IP_INVESTIGATION_VIEWED,
        result=AuditResult.SUCCESS,
        actor_user_id=current_user.id,
        actor_email=current_user.email,
        resource_type="NETWORK_IP",
        ip_address=ip_address,
        metadata={"target_ip": ip_address, "total_events": total},
    )
    db.commit()

    if total == 0:
        return NetworkIPDetailResponse(
            ip_address=ip_address, first_seen=first_seen, last_seen=last_seen,
            total_events=0, unique_destinations=0, unique_sources=0,
            unique_ports=0, protocols=[], related_detections=0, related_alerts=0,
        )

    return NetworkIPDetailResponse(
        ip_address=ip_address,
        first_seen=first_seen,
        last_seen=last_seen,
        total_events=total,
        unique_destinations=unique_destinations,
        unique_sources=unique_sources,
        unique_ports=unique_ports,
        protocols=sorted(p for p in protocols if p),
        related_detections=related_det_count,
        related_alerts=related_alert_count,
    )


@router.get("/ports", response_model=NetworkPortListResponse)
def list_ports(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    analysis_run_id: str | None = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    port_agg = (
        select(
            NetworkEvent.source_port.label("port"),
            func.max(NetworkEvent.protocol).label("protocol"),
            func.count().label("event_count"),
            func.count(func.distinct(NetworkEvent.source_ip)).label("unique_sources"),
            func.count(func.distinct(NetworkEvent.destination_ip)).label("unique_destinations"),
            func.min(NetworkEvent.timestamp).label("first_seen"),
            func.max(NetworkEvent.timestamp).label("last_seen"),
        )
        .where(NetworkEvent.source_port.isnot(None))
        .group_by(NetworkEvent.source_port)
    )

    if from_timestamp:
        dt = _parse_iso(from_timestamp)
        if dt:
            port_agg = port_agg.where(NetworkEvent.timestamp >= dt)
    if to_timestamp:
        dt = _parse_iso(to_timestamp)
        if dt:
            port_agg = port_agg.where(NetworkEvent.timestamp <= dt)
    if analysis_run_id:
        port_agg = port_agg.where(NetworkEvent.analysis_run_id == analysis_run_id)

    sub = port_agg.subquery()
    count_stmt = select(func.count()).select_from(sub)
    total = db.scalar(count_stmt) or 0
    total_pages = max((total + page_size - 1) // page_size, 1)

    rows = db.execute(
        select(sub).order_by(sub.c.event_count.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()

    items = [
        NetworkPortResponse(
            port=r.port, protocol=r.protocol, event_count=r.event_count,
            unique_sources=r.unique_sources, unique_destinations=r.unique_destinations,
            first_seen=r.first_seen, last_seen=r.last_seen,
        )
        for r in rows
    ]

    return NetworkPortListResponse(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


@router.get("/protocols", response_model=NetworkProtocolListResponse)
def list_protocols(
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    analysis_run_id: str | None = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    base = select(NetworkEvent).where(NetworkEvent.protocol.isnot(None))
    if from_timestamp:
        dt = _parse_iso(from_timestamp)
        if dt:
            base = base.where(NetworkEvent.timestamp >= dt)
    if to_timestamp:
        dt = _parse_iso(to_timestamp)
        if dt:
            base = base.where(NetworkEvent.timestamp <= dt)
    if analysis_run_id:
        base = base.where(NetworkEvent.analysis_run_id == analysis_run_id)

    sub = base.subquery()
    total = db.scalar(select(func.count()).select_from(select(NetworkEvent).subquery())) or 0

    protocol_counts = db.execute(
        select(sub.c.protocol, func.count().label("cnt"))
        .group_by(sub.c.protocol)
        .order_by(text("cnt DESC"))
    ).all()

    items = [
        NetworkProtocolResponse(
            protocol=r.protocol,
            event_count=r.cnt,
            percentage=round(r.cnt / total * 100, 2) if total > 0 else 0,
        )
        for r in protocol_counts
    ]

    return NetworkProtocolListResponse(items=items)


@router.get("/top-talkers", response_model=NetworkTopTalkerListResponse)
def list_top_talkers(
    limit: int = Query(25, ge=1, le=100),
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    analysis_run_id: str | None = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    base = select(NetworkEvent).where(NetworkEvent.source_ip.isnot(None))
    if from_timestamp:
        dt = _parse_iso(from_timestamp)
        if dt:
            base = base.where(NetworkEvent.timestamp >= dt)
    if to_timestamp:
        dt = _parse_iso(to_timestamp)
        if dt:
            base = base.where(NetworkEvent.timestamp <= dt)
    if analysis_run_id:
        base = base.where(NetworkEvent.analysis_run_id == analysis_run_id)

    sub = base.subquery()

    src_agg = db.execute(
        select(
            sub.c.source_ip.label("ip_address"),
            func.count().label("connection_count"),
            func.count(func.distinct(sub.c.destination_ip)).label("unique_destinations"),
            func.count(func.distinct(sub.c.source_ip)).label("unique_sources_dummy"),
            func.count(func.distinct(
                case(
                    (sub.c.source_port.isnot(None), sub.c.source_port),
                    else_=sub.c.destination_port,
                )
            )).label("unique_ports"),
        )
        .group_by(sub.c.source_ip)
        .order_by(text("connection_count DESC"))
        .limit(limit)
    ).all()

    dst_agg = db.execute(
        select(
            sub.c.destination_ip.label("ip_address"),
            func.count().label("connection_count"),
            func.count(func.distinct(sub.c.source_ip)).label("unique_sources"),
            func.count(func.distinct(sub.c.destination_ip)).label("unique_destinations_dummy"),
            func.count(func.distinct(
                case(
                    (sub.c.destination_port.isnot(None), sub.c.destination_port),
                    else_=sub.c.source_port,
                )
            )).label("unique_ports"),
        )
        .where(sub.c.destination_ip.isnot(None))
        .group_by(sub.c.destination_ip)
        .order_by(text("connection_count DESC"))
        .limit(limit)
    ).all()

    combined: dict[str, dict] = {}
    for row in src_agg:
        ip = row.ip_address
        if ip not in combined:
            combined[ip] = {"ip_address": ip, "connection_count": 0, "unique_destinations": 0, "unique_sources": 0, "unique_ports": 0, "direction": "source"}
        combined[ip]["connection_count"] += row.connection_count
        combined[ip]["unique_destinations"] = max(combined[ip]["unique_destinations"], row.unique_destinations)
        combined[ip]["unique_ports"] = max(combined[ip]["unique_ports"], row.unique_ports)

    for row in dst_agg:
        ip = row.ip_address
        if ip not in combined:
            combined[ip] = {"ip_address": ip, "connection_count": 0, "unique_destinations": 0, "unique_sources": 0, "unique_ports": 0, "direction": "destination"}
        combined[ip]["connection_count"] += row.connection_count
        combined[ip]["unique_sources"] = max(combined[ip]["unique_sources"], row.unique_sources)
        combined[ip]["unique_ports"] = max(combined[ip]["unique_ports"], row.unique_ports)
        if combined[ip]["direction"] == "source":
            combined[ip]["direction"] = "both"

    items = sorted(combined.values(), key=lambda x: x["connection_count"], reverse=True)[:limit]

    return NetworkTopTalkerListResponse(
        items=[NetworkTopTalkerResponse(**t) for t in items]
    )


@router.get("/timeline", response_model=NetworkTimelineResponse)
def get_timeline(
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    analysis_run_id: str | None = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    base = select(NetworkEvent).where(NetworkEvent.timestamp.isnot(None))
    if from_timestamp:
        dt = _parse_iso(from_timestamp)
        if dt:
            base = base.where(NetworkEvent.timestamp >= dt)
    if to_timestamp:
        dt = _parse_iso(to_timestamp)
        if dt:
            base = base.where(NetworkEvent.timestamp <= dt)
    if analysis_run_id:
        base = base.where(NetworkEvent.analysis_run_id == analysis_run_id)

    sub = base.subquery()

    min_ts = db.scalar(select(func.min(sub.c.timestamp)))
    max_ts = db.scalar(select(func.max(sub.c.timestamp)))

    if min_ts is None or max_ts is None:
        return NetworkTimelineResponse(items=[], interval="none")

    diff_seconds = (max_ts - min_ts).total_seconds()
    if diff_seconds <= 3600:
        interval = "minute"
    elif diff_seconds <= 86400:
        interval = "hour"
    else:
        interval = "day"

    all_events = db.scalars(
        select(sub.c.timestamp).where(sub.c.timestamp.isnot(None)).order_by(sub.c.timestamp)
    ).all()

    from collections import Counter
    buckets: Counter[datetime] = Counter()
    for ts in all_events:
        if interval == "minute":
            bucket = ts.replace(second=0, microsecond=0)
        elif interval == "hour":
            bucket = ts.replace(minute=0, second=0, microsecond=0)
        else:
            bucket = ts.replace(hour=0, minute=0, second=0, microsecond=0)
        buckets[bucket] += 1

    items = [NetworkTimelinePoint(timestamp=ts, event_count=cnt) for ts, cnt in sorted(buckets.items())]

    return NetworkTimelineResponse(items=items, interval=interval)


@router.get("/events/{event_id}", response_model=NetworkEventDetailResponse)
def get_network_event_detail(
    event_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    event = db.get(NetworkEvent, event_id)
    if event is None:
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Network event not found.")

    related_dets = []
    related_als = []

    if event.detection_id:
        det = db.get(Detection, event.detection_id)
        if det:
            related_dets.append({
                "id": det.id, "detection_type": det.detection_type,
                "title": det.title, "severity": det.severity, "status": det.status,
            })

    if event.alert_id:
        al = db.get(Alert, event.alert_id)
        if al:
            related_als.append({
                "id": al.id, "title": al.title, "severity": al.severity,
                "status": al.status, "source": al.source,
            })

    if event.analysis_run_id:
        run_dets = db.scalars(
            select(Detection).where(Detection.analysis_run_id == event.analysis_run_id)
        ).all()
        for d in run_dets:
            if d.id != event.detection_id:
                related_dets.append({
                    "id": d.id, "detection_type": d.detection_type,
                    "title": d.title, "severity": d.severity, "status": d.status,
                })
        run_als = db.scalars(
            select(Alert).where(Alert.detection_id.in_([d.id for d in run_dets]))
        ).all()
        for a in run_als:
            if a.id != event.alert_id:
                related_als.append({
                    "id": a.id, "title": a.title, "severity": a.severity,
                    "status": a.status, "source": a.source,
                })

    audit = AuditService(db)
    audit.record(
        action=AuditAction.NETWORK_EVENT_VIEWED,
        result=AuditResult.SUCCESS,
        actor_user_id=current_user.id,
        actor_email=current_user.email,
        resource_type="NETWORK_EVENT",
        resource_id=event.id,
        ip_address=_get_ip(request),
    )
    db.commit()

    return NetworkEventDetailResponse(
        event=event, related_detections=related_dets, related_alerts=related_als,
    )
