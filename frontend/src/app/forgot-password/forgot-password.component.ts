/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { UserService } from "../Services/user.service";
import { SecurityQuestionService } from "../Services/security-question.service";
import {
  type AbstractControl,
  UntypedFormControl,
  Validators,
  FormsModule,
  ReactiveFormsModule,
} from "@angular/forms";
import { Component, OnInit, inject } from "@angular/core";
import { type SecurityQuestion } from "../Models/securityQuestion.model";
import { TranslateService, TranslateModule } from "@ngx-translate/core";
import { MatButtonModule } from "@angular/material/button";
import { PasswordStrengthComponent } from "../password-strength/password-strength.component";
import { PasswordStrengthInfoComponent } from "../password-strength-info/password-strength-info.component";
import { MatSlideToggle } from "@angular/material/slide-toggle";
import { MatTooltip } from "@angular/material/tooltip";
import { MatIconModule } from "@angular/material/icon";
import { MatInputModule } from "@angular/material/input";
import {
  MatFormFieldModule,
  MatLabel,
  MatSuffix,
  MatError,
  MatHint,
} from "@angular/material/form-field";
import { MatCardModule } from "@angular/material/card";
import { MatSelect } from "@angular/material/select";
import { MatOption } from "@angular/material/core";
import { library } from "@fortawesome/fontawesome-svg-core";
import { faSave } from "@fortawesome/free-solid-svg-icons";
import { faEdit } from "@fortawesome/free-regular-svg-icons";

library.add(faSave, faEdit);

@Component({
  selector: "app-forgot-password",
  templateUrl: "./forgot-password.component.html",
  styleUrls: ["./forgot-password.component.scss"],
  imports: [
    MatCardModule,
    TranslateModule,
    MatFormFieldModule,
    MatLabel,
    MatInputModule,
    FormsModule,
    ReactiveFormsModule,
    MatIconModule,
    MatSuffix,
    MatTooltip,
    MatError,
    MatHint,
    MatSlideToggle,
    PasswordStrengthComponent,
    PasswordStrengthInfoComponent,
    MatButtonModule,
    MatSelect,
    MatOption,
  ],
})
export class ForgotPasswordComponent implements OnInit {
  private readonly securityQuestionService = inject(SecurityQuestionService);
  private readonly userService = inject(UserService);
  private readonly translate = inject(TranslateService);

  public emailControl: UntypedFormControl = new UntypedFormControl("", [
    Validators.required,
    Validators.email,
  ]);
  public securityQuestionControl: UntypedFormControl = new UntypedFormControl(
    { disabled: true, value: "" },
    [Validators.required],
  );
  public securityAnswerControl: UntypedFormControl = new UntypedFormControl(
    { disabled: true, value: "" },
    [Validators.required],
  );
  public passwordControl: UntypedFormControl = new UntypedFormControl(
    { disabled: true, value: "" },
    [Validators.required, Validators.minLength(5)],
  );
  public repeatPasswordControl: UntypedFormControl = new UntypedFormControl(
    { disabled: true, value: "" },
    [Validators.required, matchValidator(this.passwordControl)],
  );

  public securityQuestions: SecurityQuestion[] = [];
  public error?: string;
  public isRateLimited = false;
  public confirmation?: string;
  public timeoutDuration = 1000;
  private timeout;

  ngOnInit(): void {
    this.securityQuestionService.find(null).subscribe({
      next: (questions: any) => {
        this.securityQuestions = questions;
      },
      error: (err) => {
        console.log(err);
      },
    });

    this.emailControl.valueChanges.subscribe(() => {
      this.onEmailChange();
    });
  }

  onEmailChange() {
    clearTimeout(this.timeout);
    this.timeout = setTimeout(() => {
      if (this.emailControl.valid) {
        this.securityQuestionControl.enable();
        this.securityAnswerControl.enable();
        this.passwordControl.enable();
        this.repeatPasswordControl.enable();
      } else {
        this.securityQuestionControl.disable();
        this.securityAnswerControl.disable();
        this.passwordControl.disable();
        this.repeatPasswordControl.disable();
      }
    }, this.timeoutDuration);
  }

  resetPassword() {
    this.userService
      .resetPassword({
        email: this.emailControl.value,
        answer: this.securityAnswerControl.value,
        new: this.passwordControl.value,
        repeat: this.repeatPasswordControl.value,
      })
      .subscribe({
        next: () => {
          this.error = undefined;
          this.translate.get("PASSWORD_SUCCESSFULLY_CHANGED").subscribe({
            next: (msg) => {
              this.confirmation = msg;
            },
            error: (id) => {
              this.confirmation = id;
            },
          });
          this.resetForm();
        },
        error: (err) => {
          this.isRateLimited = err.status === 429;
          this.error = this.isRateLimited
            ? "Too many reset password attempts. Please try again in 15 minutes."
            : (err.error?.error ??
              err.error ??
              "Wrong answer to security question.");
          this.confirmation = undefined;
          this.resetErrorForm();
        },
      });
  }

  resetForm() {
    this.emailControl.setValue("");
    this.emailControl.markAsPristine();
    this.emailControl.markAsUntouched();
    this.securityQuestionControl.setValue("");
    this.securityQuestionControl.markAsPristine();
    this.securityQuestionControl.markAsUntouched();
    this.securityAnswerControl.setValue("");
    this.securityAnswerControl.markAsPristine();
    this.securityAnswerControl.markAsUntouched();
    this.passwordControl.setValue("");
    this.passwordControl.markAsPristine();
    this.passwordControl.markAsUntouched();
    this.repeatPasswordControl.setValue("");
    this.repeatPasswordControl.markAsPristine();
    this.repeatPasswordControl.markAsUntouched();
  }

  resetErrorForm() {
    this.emailControl.markAsPristine();
    this.emailControl.markAsUntouched();
    this.securityQuestionControl.markAsPristine();
    this.securityQuestionControl.markAsUntouched();
    this.securityAnswerControl.setValue("");
    this.securityAnswerControl.markAsPristine();
    this.securityAnswerControl.markAsUntouched();
    this.passwordControl.setValue("");
    this.passwordControl.markAsPristine();
    this.passwordControl.markAsUntouched();
    this.repeatPasswordControl.setValue("");
    this.repeatPasswordControl.markAsPristine();
    this.repeatPasswordControl.markAsUntouched();
  }
}

function matchValidator(passwordControl: AbstractControl) {
  return function matchOtherValidate(
    repeatPasswordControl: UntypedFormControl,
  ) {
    const password = passwordControl.value;
    const passwordRepeat = repeatPasswordControl.value;
    if (password !== passwordRepeat) {
      return { notSame: true };
    }
    return null;
  };
}
