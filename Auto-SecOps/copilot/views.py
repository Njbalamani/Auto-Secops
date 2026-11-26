from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from config.ui import can_manage, organization_for_request
from copilot.services import answer_question, build_briefing


@login_required
def workspace(request):
    organization = organization_for_request(request)
    if not organization:
        return render(request, "copilot/workspace.html", {"error": "No organization assigned."})

    briefing = build_briefing(organization, request.user)
    answer = None
    question = ""
    if request.method == "POST" and can_manage(request):
        question = request.POST.get("question", "")
        if question.strip():
            answer = answer_question(organization, question, request.user)
        else:
            messages.error(request, "Enter a question for the copilot.")

    return render(
        request,
        "copilot/workspace.html",
        {
            "briefing": briefing,
            "answer": answer,
            "question": question,
            "error": "",
            "can_manage_view": can_manage(request),
        },
    )
