"""
Seed Database Script for ISU Lost & Found
Run this script to populate the database with sample data for testing.

Usage: python seed_database.py
Or double-click run_seed.bat
"""

import os
import sys
from datetime import datetime, timedelta
import random

# Add the parent directory to path to import app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, ItemReport, ClaimRequest, bcrypt, generate_claim_code

# Sample ISU Cauayan Campus Locations
LOCATIONS = [
    "Main Gate / Entrance Arch",
    "Administration Building",
    "CIT Building / Computer Labs",
    "Engineering Building",
    "Library / Learning Resource Center",
    "Canteen / Food Court Area",
    "Gymnasium / Sports Complex",
    "Student Center / Lobby",
    "Parking Area",
    "SCC Office",
]

# Sample items commonly lost/found on campus
LOST_ITEMS = [
    ("Black Leather Wallet", "Black leather wallet with ISU ID, ATM card, and some cash. Has a small tear on the side."),
    ("Blue Umbrella", "Foldable blue umbrella with wooden handle. Brand is Fibrella."),
    ("Scientific Calculator Casio", "Casio scientific calculator fx-991ES Plus. Has my name written on the back."),
    ("House Keys with Keychain", "Set of 3 keys with a blue ISU lanyard keychain."),
    ("iPhone Charger", "White Apple iPhone charger with lightning cable."),
    ("Eyeglasses Black Frame", "Prescription eyeglasses with black rectangular frame."),
    ("Red Backpack", "Red Jansport backpack with notebooks and pencil case inside."),
    ("Student ID Card", "ISU student ID card with lanyard. Need it for exams."),
    ("Laptop Charger Dell", "Dell laptop charger, black, 65W."),
    ("Water Bottle Blue", "Blue stainless steel water bottle with stickers."),
]

FOUND_ITEMS = [
    ("Brown Wallet Found", "Found a brown leather wallet near the canteen. Contains some cash and ID."),
    ("Black Umbrella", "Found black automatic umbrella near library entrance."),
    ("Calculator Found", "Found a Casio calculator in computer lab. Has writings on back."),
    ("Set of Keys", "Found keys with lanyard near parking area. About 3-4 keys."),
    ("Blue Tumbler", "Found blue stainless steel tumbler near gymnasium."),
    ("Notebook Engineering", "Found spiral notebook with engineering notes."),
    ("USB Flash Drive", "Found 16GB Sandisk USB in library. Has documents."),
    ("White Earphones", "Found white wired earphones near student center."),
    ("ID Lace with Cards", "Found ID lace with student ID and ATM card."),
    ("Prescription Glasses", "Found eyeglasses with blue frame near admin building."),
]

USERS = [
    ("Juan Dela Cruz", "juan@isu.edu.ph"),
    ("Maria Santos", "maria@isu.edu.ph"),
    ("Pedro Reyes", "pedro@isu.edu.ph"),
    ("Ana Garcia", "ana@isu.edu.ph"),
    ("Jose Rizal", "jose@isu.edu.ph"),
    ("Elena Cruz", "elena@isu.edu.ph"),
]


def seed():
    print("=" * 50)
    print("   ISU LOST & FOUND - DATABASE SEEDER")
    print("=" * 50)
    
    with app.app_context():
        # Clear existing test data
        print("\n[1/4] Clearing old test data...")
        ClaimRequest.query.delete()
        ItemReport.query.delete()
        User.query.filter(User.email != 'admin@isu.edu').delete()
        db.session.commit()
        print("      Done!")
        
        # Create users
        print("\n[2/4] Creating sample users...")
        users = []
        for name, email in USERS:
            user = User(
                name=name,
                email=email,
                password=bcrypt.generate_password_hash("password123").decode('utf-8'),
                role="user"
            )
            db.session.add(user)
            users.append(user)
            print(f"      + {name} ({email})")
        db.session.commit()
        
        # Create reports
        print("\n[3/4] Creating sample reports...")
        all_reports = []
        
        # Lost items
        print("      Lost Items:")
        for i, (title, desc) in enumerate(LOST_ITEMS):
            user = users[i % len(users)]
            report = ItemReport(
                title=title,
                description=desc,
                location=random.choice(LOCATIONS),
                type="lost",
                status="approved",
                reporter_id=user.id,
                date_time=datetime.utcnow() - timedelta(days=random.randint(1, 14)),
                created_at=datetime.utcnow() - timedelta(days=random.randint(1, 14))
            )
            db.session.add(report)
            all_reports.append(report)
            print(f"        - {title}")
        
        # Found items
        print("      Found Items:")
        for i, (title, desc) in enumerate(FOUND_ITEMS):
            user = users[(i + 3) % len(users)]
            report = ItemReport(
                title=title,
                description=desc,
                location=random.choice(LOCATIONS),
                type="found",
                status="approved",
                reporter_id=user.id,
                date_time=datetime.utcnow() - timedelta(days=random.randint(1, 14)),
                created_at=datetime.utcnow() - timedelta(days=random.randint(1, 14))
            )
            db.session.add(report)
            all_reports.append(report)
            print(f"        - {title}")
        
        # Add pending reports
        pending1 = ItemReport(
            title="Lost Phone Case",
            description="Clear phone case for iPhone, lost near parking.",
            location="Parking Area",
            type="lost",
            status="pending",
            reporter_id=users[0].id,
            date_time=datetime.utcnow() - timedelta(days=1),
            created_at=datetime.utcnow() - timedelta(hours=5)
        )
        pending2 = ItemReport(
            title="Found Watch",
            description="Silver wristwatch found near gym.",
            location="Gymnasium / Sports Complex",
            type="found",
            status="pending",
            reporter_id=users[1].id,
            date_time=datetime.utcnow() - timedelta(days=1),
            created_at=datetime.utcnow() - timedelta(hours=3)
        )
        db.session.add(pending1)
        db.session.add(pending2)
        db.session.commit()
        print("      Pending (for admin review):")
        print("        - Lost Phone Case")
        print("        - Found Watch")
        
        # Create claims
        print("\n[4/4] Creating sample claims...")
        found_reports = [r for r in all_reports if r.type == 'found']
        
        # Pending claims
        for i in range(3):
            report = found_reports[i]
            claimer = [u for u in users if u.id != report.reporter_id][0]
            claim = ClaimRequest(
                item_id=report.id,
                claimer_id=claimer.id,
                message="I believe this is my item. I can provide more details.",
                status="pending",
                request_date=datetime.utcnow() - timedelta(hours=random.randint(1, 48))
            )
            db.session.add(claim)
            print(f"      + Pending claim on '{report.title}'")
        
        # Approved claim
        report = found_reports[3]
        claimer = [u for u in users if u.id != report.reporter_id][1]
        claim = ClaimRequest(
            item_id=report.id,
            claimer_id=claimer.id,
            message="This is definitely my item!",
            status="accepted",
            claim_code=generate_claim_code(),
            pickup_location="SCC Office",
            pickup_contact="SCC Staff",
            pickup_instructions="Office hours: 8AM-5PM, Mon-Fri. Bring student ID.",
            request_date=datetime.utcnow() - timedelta(days=2)
        )
        db.session.add(claim)
        report.status = "claimed"
        db.session.commit()
        print(f"      + Approved claim on '{report.title}' (Code: {claim.claim_code})")
        
        # Summary
        print("\n" + "=" * 50)
        print("   SEEDING COMPLETE!")
        print("=" * 50)
        print(f"\n   Total Users:   {User.query.count()}")
        print(f"   Total Reports: {ItemReport.query.count()}")
        print(f"   - Lost:        {ItemReport.query.filter_by(type='lost').count()}")
        print(f"   - Found:       {ItemReport.query.filter_by(type='found').count()}")
        print(f"   - Pending:     {ItemReport.query.filter_by(status='pending').count()}")
        print(f"   Total Claims:  {ClaimRequest.query.count()}")
        
        print("\n" + "=" * 50)
        print("   TEST ACCOUNTS")
        print("=" * 50)
        print("\n   Admin:")
        print("     Email:    admin@isu.edu")
        print("     Password: admin123")
        print("\n   Sample Users (password: password123):")
        print("     - juan@isu.edu.ph")
        print("     - maria@isu.edu.ph")
        print("     - pedro@isu.edu.ph")
        print("\n   Visit: http://127.0.0.1:5000")
        print("=" * 50)


if __name__ == "__main__":
    seed()

