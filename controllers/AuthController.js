const User = require("../models/User");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const {Op} = require("sequelize");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "phpitladiplomado@gmail.com",
    pass: "#Querty123",
  },
});

exports.GetLogin = (req, res, next) => {
  res.render("auth/login", {
    pageTitle: "Login",
    loginCSS: true,
    loginActive: true,
  });
};

exports.PostLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  User.findOne({ where: { email: email } })
    .then((user) => {
      if (!user) {
        req.flash("errors", "email is invalid ");
        return res.redirect("/login");
      }

      bcrypt
        .compare(password, user.password)
        .then((result) => {
          if (result) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save((err) => {
              console.log(err);
              res.redirect("/");
            });
          }
          req.flash("errors", "password is invalid");
          res.redirect("/login");
        })
        .catch((err) => {
          console.log(err);
          req.flash(
            "errors",
            "An error has occurred contact the administrator."
          );
          res.redirect("/login");
        });
    })
    .catch((err) => {
      console.log(err);
      req.flash("errors", "An error has occurred contact the administrator.");
      res.redirect("/login");
    });
};

exports.Logout = (req, res, next) => {
  req.session.destroy((err) => {
    console.log(err);
    res.redirect("/");
  });
};

exports.GetSignup = (req, res, next) => {
  res.render("auth/signup", {
    pageTitle: "Signup",
    signupActive: true,
  });
};

exports.PostSignup = (req, res, next) => {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;

  if (password != confirmPassword) {
    req.flash("errors", "Password and confirm password no equals");
    return res.redirect("/signup");
  }

  User.findOne({ where: { email: email } })
    .then((user) => {
      if (user) {
        req.flash(
          "errors",
          "email exits already, please pick a different one "
        );
        return res.redirect("/signup");
      }

      bcrypt
        .hash(password, 12)
        .then((hashedPassword) => {
          User.create({ name: name, email: email, password: hashedPassword })
            .then((user) => {
              res.redirect("/login");
            })
            .catch((err) => {
              console.log(err);
            });
        })
        .catch((err) => {
          console.log(err);
        });
    })
    .catch((err) => {
      console.log(err);
    });
};

exports.GetReset = (req, res, next) => {
  res.render("auth/reset", {
    pageTitle: "Reset",
    loginCSS: true,
    loginActive: true,
  });
};

exports.PostReset = (req, res, next) => {
  const email = req.body.email;

  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect("/reset");
    }

    const token = buffer.toString("hex");

    User.findOne({ where: { email: email } })
      .then((user) => {
        if (!user) {
          req.flash("errors", "no existe una cuenta con este correo");
          return null;
        }

        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000;
        return user.save();
      })
      .then((result) => {
        let urlRedirect = "/reset";

        if (result) {
          urlRedirect = "/login";

          transporter.sendMail({
            from: "phpitladiplomado@gmail.com",
            to: "leonardotv.93@gmail.com",
            subject: `Password reset`,
            html: `<h3> USted solicito un cambio de contrasenia </h3>
               
                  <p> Haga click en este <a href="http://localhost:5000/reset/${token}"> link </a> para colocar una nueva contrasenia </p>

               `,
          });
        }

        res.redirect(urlRedirect);
      })
      .catch((err) => {
        console.log(err);
      });
  });
};

exports.GetNewPassword = (req, res, next) => {
  const token = req.params.token;

  User.findOne({ where: { resetToken: token, resetTokenExpiration: {[Op.gte]: Date.now()} } })
    .then((user) => {
      if (!user) {
        req.flash("errors", "no existe esta cuenta");
        return res.redirect("/reset");
      }

      res.render("auth/new-password", {
        pageTitle: "Reset",
        loginCSS: true,
        loginActive: true,
        passwordToken: token,
        userId: user.id,
      });
    })
    .catch((err) => {
      console.log(err);
    });
};

exports.PostNewPassword = (req, res, next) => {
  const newPassword = req.body.password;
  const confirmPassword = req.body.confirmPassword;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;

  if (newPassword != confirmPassword) {
    req.flash("errors", "No coincide las contrasenia");
    return res.redirect("/login");
  }

  User.findOne({
    where: {
      resetToken: passwordToken,
      id: userId,
      resetTokenExpiration: { [Op.gte]: Date.now() },
    },
  })
    .then((user) => {
      //promise

      if (!user) {
        req.flash("errors", "no existe esta cuenta");
        return res.redirect("/reset");
      }

      bcrypt
        .hash(newPassword, 12)
        .then((hashedPassword) => {
          user.password = hashedPassword;
          user.resetToken = null;
          user.resetTokenExpiration = null;
          return user.save();
        })
        .catch((err) => {
          console.log(err);
        });

      res.redirect("/login");
    })
    .catch((err) => {
      console.log(err);
    });
};
